#include <windows.h>
#include <cstdio>
#include <cwchar>

namespace
{
constexpr wchar_t Path[] = L"Software\\Wine\\Mac Driver";
constexpr wchar_t Parent[] = L"Software\\Wine";
constexpr wchar_t Leaf[] = L"Mac Driver";
constexpr wchar_t Name[] = L"RetinaMode";
constexpr wchar_t Override[] = L"Y";
constexpr unsigned MaxLength = 64;

enum class State { absentKey, absentValue, value };

struct Snapshot
{
    State state = State::absentKey;
    wchar_t text[MaxLength + 1]{};
};

struct Key
{
    HKEY handle = nullptr;
    ~Key() { if (handle) RegCloseKey(handle); }
};

bool Absent(LSTATUS status)
{
    return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

bool BoundedAscii(const wchar_t* text, unsigned& length)
{
    for (length = 0; length <= MaxLength; ++length)
    {
        if (!text[length])
            return true;
        if (text[length] < L' ' || text[length] > L'~')
            return false;
    }
    return false;
}

void Print(const char* state, const wchar_t* text = L"")
{
    std::printf("{\"state\":\"%s\",\"value\":\"", state);
    for (const auto* p = text; *p; ++p)
    {
        if (*p == L'"' || *p == L'\\')
            std::putchar('\\');
        std::putchar(static_cast<int>(*p));
    }
    std::puts("\"}");
}

int Report(State state, const wchar_t* text = L"")
{
    Print(state == State::absentKey ? "absent_key" : state == State::absentValue ? "absent_value" : "value", text);
    return std::fflush(stdout) == EOF || std::ferror(stdout) ? 1 : 0;
}

int Failure(LSTATUS status)
{
    if (status == ERROR_INVALID_DATA || status == ERROR_MORE_DATA)
    {
        Print("unsupported");
        return 4;
    }
    Print("error");
    std::fprintf(stderr, "win32=%lu\n", static_cast<unsigned long>(status));
    return 1;
}

LSTATUS ReadValue(HKEY key, Snapshot& output)
{
    if (!key)
        return ERROR_SUCCESS;
    DWORD type = 0, bytes = sizeof(output.text);
    const auto status = RegQueryValueExW(key, Name, nullptr, &type, reinterpret_cast<BYTE*>(output.text), &bytes);
    if (status == ERROR_FILE_NOT_FOUND)
    {
        output.state = State::absentValue;
        output.text[0] = L'\0';
        return ERROR_SUCCESS;
    }
    if (status != ERROR_SUCCESS)
        return status;
    if (type != REG_SZ || bytes < sizeof(wchar_t) || bytes > sizeof(output.text) || bytes % sizeof(wchar_t))
        return ERROR_INVALID_DATA;
    unsigned length;
    if (output.text[bytes / sizeof(wchar_t) - 1] != L'\0' || !BoundedAscii(output.text, length)
        || (length + 1) * sizeof(wchar_t) != bytes)
        return ERROR_INVALID_DATA;
    output.state = State::value;
    return ERROR_SUCCESS;
}

LSTATUS WriteValue(HKEY key, const wchar_t* text)
{
    const auto bytes = static_cast<DWORD>((std::wcslen(text) + 1) * sizeof(wchar_t));
    return RegSetValueExW(key, Name, 0, REG_SZ, reinterpret_cast<const BYTE*>(text), bytes);
}

LSTATUS RemoveEmptyLeaf(HKEY key, bool& removed)
{
    DWORD subkeys = 0, values = 0;
    const auto status = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
        &values, nullptr, nullptr, nullptr, nullptr);
    if (status != ERROR_SUCCESS || subkeys || values)
        return status;
    // The controller holds the Source-prefix lock around this non-atomic empty check and deletion.
    const auto deletion = RegDeleteKeyW(HKEY_CURRENT_USER, Path);
    removed = deletion == ERROR_SUCCESS;
    return deletion;
}

int Apply(Key& key)
{
    DWORD disposition = 0;
    if (!key.handle)
    {
        Key parent;
        const auto opened = RegOpenKeyExW(HKEY_CURRENT_USER, Parent, 0, KEY_CREATE_SUB_KEY, &parent.handle);
        if (opened != ERROR_SUCCESS)
            return Failure(opened);
        const auto created = RegCreateKeyExW(parent.handle, Leaf, 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &key.handle, &disposition);
        if (created != ERROR_SUCCESS)
            return Failure(created);
    }
    Snapshot current;
    auto status = ReadValue(key.handle, current);
    if (status == ERROR_SUCCESS)
        status = WriteValue(key.handle, Override);
    if (status == ERROR_SUCCESS)
        return Report(State::value, Override);
    if (disposition == REG_CREATED_NEW_KEY)
    {
        bool removed = false;
        RemoveEmptyLeaf(key.handle, removed);
    }
    return Failure(status);
}

int Restore(HKEY key, const Snapshot& current, State prior, const wchar_t* text)
{
    if (current.state == prior && (prior != State::value || !std::wcscmp(current.text, text)))
        return Report(prior, text);

    // An already absent value does not establish ownership of the key left behind.
    if (prior == State::absentKey && current.state == State::absentValue)
        return Report(State::absentValue);
    if (current.state != State::value || std::wcscmp(current.text, Override))
    {
        Print("conflict");
        return 3;
    }

    if (prior == State::value)
    {
        const auto status = WriteValue(key, text);
        return status == ERROR_SUCCESS ? Report(prior, text) : Failure(status);
    }

    const auto status = RegDeleteValueW(key, Name);
    if (status != ERROR_SUCCESS)
        return Failure(status);
    if (prior == State::absentValue)
        return Report(prior);
    bool removed = false;
    const auto deletion = RemoveEmptyLeaf(key, removed);
    return deletion == ERROR_SUCCESS ? Report(removed ? State::absentKey : State::absentValue) : Failure(deletion);
}
}

int wmain(int argc, wchar_t** argv)
{
    const bool query = argc == 2 && !std::wcscmp(argv[1], L"query");
    const bool apply = argc == 2 && !std::wcscmp(argv[1], L"apply");
    bool restore = argc >= 3 && !std::wcscmp(argv[1], L"restore");
    State prior = State::absentKey;
    const wchar_t* text = L"";
    unsigned length;
    if (restore && argc == 3 && !std::wcscmp(argv[2], L"absent_key"))
        prior = State::absentKey;
    else if (restore && argc == 3 && !std::wcscmp(argv[2], L"absent_value"))
        prior = State::absentValue;
    else if (restore && argc == 4 && !std::wcscmp(argv[2], L"value") && BoundedAscii(argv[3], length))
    {
        prior = State::value;
        text = argv[3];
    }
    else
        restore = false;

    if (!query && !apply && !restore)
    {
        Print("usage");
        return 2;
    }

    Key key;
    const auto access = query ? KEY_QUERY_VALUE : KEY_QUERY_VALUE | KEY_SET_VALUE;
    const auto status = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, access, &key.handle);
    if (status != ERROR_SUCCESS)
    {
        key.handle = nullptr;
        if (!Absent(status))
            return Failure(status);
    }
    if (apply)
        return Apply(key);
    Snapshot current;
    const auto read = ReadValue(key.handle, current);
    if (read != ERROR_SUCCESS)
        return Failure(read);
    if (restore)
        return Restore(key.handle, current, prior, text);
    return Report(current.state, current.text);
}
