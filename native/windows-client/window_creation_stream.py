"""Filter one existing binary Popen stream before writing the baseline text log."""
import os
import re
import select
import threading

MAX_LINE_BYTES = 16384
_WIN = re.compile(r'(?:^|:)(?:trace|warn|err|fixme):win:|^(?:[^\s:]*:)*win:', re.IGNORECASE)


class WindowCreationStream:
    def __init__(self, collector):
        self.collector = collector
        self.process = self.output = self.thread = self.pipe = None
        self._stop = threading.Event()
        self._finished = self._eof = False
        self._errors = {}
        self._counts = dict(complete_lines=0, accepted_lines=0, dropped_lines=0,
            dropped_win_lines=0, passthrough_lines=0, oversized_lines=0, incomplete_lines=0)

    def _error(self, phase, error):
        name = type(error).__name__
        self._errors.setdefault(phase, name if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) else 'Exception')

    def attach(self, process, output):
        if self.process is not None or self._finished:
            raise RuntimeError('Window creation stream is already attached or finished')
        self.process, self.output, self.pipe = process, output, process.stdout
        if self.pipe is None:
            raise ValueError('Window creation stream requires one binary stdout pipe')
        try:
            self._fd = self.pipe.fileno()
            self.thread = threading.Thread(target=self._drain, name='window-creation-stream', daemon=True)
            self.thread.start()
        except Exception as error:
            self._error('start', error)
            raise
        return self

    start = attach

    def _line(self, raw, complete=True):
        line = raw.decode('utf-8', errors='replace')
        if complete:
            self._counts['complete_lines'] += 1
        else:
            self._counts['incomplete_lines'] += 1
        win = bool(_WIN.search(line))
        try:
            action = self.collector.accept(line, complete=complete)
            if action not in ('accepted', 'drop', 'passthrough'):
                raise ValueError('Invalid collector action')
        except Exception as error:
            self._error('collector', error)
            action = 'drop'
        if action == 'accepted' and complete:
            self._counts['accepted_lines'] += 1
        if action == 'passthrough' and complete and not win:
            try:
                self.output.write(line)
                self._counts['passthrough_lines'] += 1
            except Exception as error:
                self._error('write', error)
                self._stop.set()
        else:
            self._counts['dropped_lines'] += 1
            if win:
                self._counts['dropped_win_lines'] += 1

    def _drain(self):
        pending = bytearray()
        dropping = False
        try:
            while not self._stop.is_set():
                if not select.select([self._fd], [], [], 0.05)[0]:
                    continue
                chunk = os.read(self._fd, 4096)
                if not chunk:
                    self._eof = True
                    break
                at = 0
                while at < len(chunk):
                    end = chunk.find(b'\n', at)
                    stop = len(chunk) if end < 0 else end + 1
                    if not dropping:
                        piece = chunk[at:stop]
                        if len(pending) + len(piece) > MAX_LINE_BYTES:
                            pending.clear()
                            dropping = True
                            self._counts['oversized_lines'] += 1
                            self._counts['dropped_lines'] += 1
                        else:
                            pending.extend(piece)
                    if end >= 0:
                        if not dropping:
                            self._line(bytes(pending))
                        pending.clear()
                        dropping = False
                    at = stop
            if pending:
                self._line(bytes(pending), complete=False)
            elif dropping:
                self._counts['incomplete_lines'] += 1
        except Exception as error:
            self._error('read', error)

    def finish_after_wineserver_cleanup(self):
        if self._finished:
            return
        self._finished = True
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=1.5)
            if self.thread.is_alive():
                self._stop.set()
                self.thread.join(timeout=0.5)
            if self.thread.is_alive():
                self._errors.setdefault('join', 'TimeoutError')
                return  # A live writer must not race a closed output.
        if self.pipe is not None:
            try:
                self.pipe.close()
            except Exception as error:
                self._error('pipe_close', error)
        if self.output is not None:
            try:
                self.output.flush()
            except Exception as error:
                self._error('flush', error)
            finally:
                try:
                    self.output.close()
                except Exception as error:
                    self._error('close', error)

    def result(self):
        stopped = self.thread is None or not self.thread.is_alive()
        try:
            numeric = self.collector.summary()
            if type(numeric) is not dict:
                raise TypeError('Invalid collector summary')
        except Exception as error:
            self._error('summary', error)
            numeric = None
        return {'stream_stats': dict(self._counts), 'numeric_window_trace': numeric,
            'error_types': dict(self._errors), 'eof_observed': self._eof,
            'reader_thread_stopped': stopped, 'finished_after_cleanup': self._finished,
            'capture_complete': bool(self.process is not None and self._finished and stopped and self._eof and not self._errors
                and not self._counts['oversized_lines'] and not self._counts['incomplete_lines']
                and numeric is not None and not numeric.get('capped', False)
                and not any(numeric.get(key, 0) for key in ('oversized_lines', 'incomplete_lines', 'invalid_lines'))),
            'win_payload_lines_persisted': False}
