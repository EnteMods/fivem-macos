#include <stdio.h>
#include <stddef.h>
#include <glib.h>
#include <glib-object.h>
#include <gst/gst.h>
#include <gst/video/video.h>
#include <gst/audio/audio.h>
#include <gst/tag/tag.h>
#include <libavutil/avutil.h>
#include <libavutil/frame.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavcodec/bsf.h>

_Static_assert(sizeof(void *) == 8, "Require 64-bit target");
_Static_assert(sizeof(gint64) == 8, "Require 64-bit gint64");
_Static_assert(GLIB_SIZEOF_VOID_P == sizeof(void *), "Require matching GLib pointer ABI");
_Static_assert(GLIB_SIZEOF_LONG == sizeof(long), "Require matching GLib long ABI");
_Static_assert(GLIB_SIZEOF_SIZE_T == sizeof(size_t), "Require matching GLib size_t ABI");

int main(void)
{
    GTypeQuery query;
    g_type_query(G_TYPE_OBJECT, &query);
    if (query.instance_size != sizeof(GObject) || query.class_size != sizeof(GObjectClass)) return 10;
    printf("GLIB header=%d.%d.%d runtime=%u.%u.%u GObject=%zu GObjectClass=%zu ABI=PASS\n",
           GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION,
           glib_major_version, glib_minor_version, glib_micro_version, sizeof(GObject), sizeof(GObjectClass));
    GError *error = NULL;
    if (!gst_init_check(NULL, NULL, &error))
    {
        fprintf(stderr, "gst_init_check failed: %s\n", error ? error->message : "no detail");
        g_clear_error(&error);
        return 11;
    }
    guint major, minor, micro, nano;
    gst_version(&major, &minor, &micro, &nano);
    g_type_query(GST_TYPE_OBJECT, &query);
    if (query.instance_size != sizeof(GstObject) || query.class_size != sizeof(GstObjectClass)) return 12;
    GstBuffer *buffer = gst_buffer_new_allocate(NULL, 64, NULL);
    if (!buffer || gst_buffer_get_size(buffer) != 64) return 13;
    GstMapInfo mapped = GST_MAP_INFO_INIT;
    if (!gst_buffer_map(buffer, &mapped, GST_MAP_WRITE) || mapped.size != 64) return 14;
    mapped.data[0] = 0x5a;
    gst_buffer_unmap(buffer, &mapped);
    gst_buffer_unref(buffer);
    GstVideoInfo video;
    gst_video_info_init(&video);
    if (!gst_video_info_set_format(&video, GST_VIDEO_FORMAT_RGBA, 16, 16) || GST_VIDEO_INFO_SIZE(&video) != 1024) return 15;
    GstAudioInfo audio;
    gst_audio_info_init(&audio);
    gst_audio_info_set_format(&audio, GST_AUDIO_FORMAT_F32LE, 48000, 2, NULL);
    if (GST_AUDIO_INFO_BPF(&audio) != 8 || !gst_tag_check_language_code("en")) return 16;
    printf("GSTREAMER header=%d.%d.%d runtime=%u.%u.%u.%u objectABI=PASS buffer=PASS video=PASS audio=PASS tag=PASS\n",
           GST_VERSION_MAJOR, GST_VERSION_MINOR, GST_VERSION_MICRO, major, minor, micro, nano);
    gst_deinit();
    if ((avutil_version() >> 16) != LIBAVUTIL_VERSION_MAJOR
            || (avformat_version() >> 16) != LIBAVFORMAT_VERSION_MAJOR
            || (avcodec_version() >> 16) != LIBAVCODEC_VERSION_MAJOR) return 17;
    AVFrame *frame = av_frame_alloc();
    if (!frame) return 18;
    av_frame_free(&frame);
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_PCM_S16LE);
    AVCodecContext *context = codec ? avcodec_alloc_context3(codec) : NULL;
    if (!context) return 19;
    avcodec_free_context(&context);
    AVFormatContext *format = avformat_alloc_context();
    if (!format) return 20;
    avformat_free_context(format);
    printf("FFMPEG runtime=%s headerVersions=%u/%u/%u runtimeVersions=%u/%u/%u headersMajor=PASS alloc=PASS\n",
           av_version_info(), LIBAVUTIL_VERSION_INT, LIBAVCODEC_VERSION_INT, LIBAVFORMAT_VERSION_INT,
           avutil_version(), avcodec_version(), avformat_version());
    return 0;
}
