/*
 * GStreamer transform backend
 *
 * Copyright 2022 Rémi Bernon for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#include <gst/gst.h>
#include <gst/video/video.h>
#include <gst/audio/audio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"
#include "mferror.h"
#include "mfapi.h"

#include "unix_private.h"

#define GST_SAMPLE_FLAG_WG_CAPS_CHANGED (GST_MINI_OBJECT_FLAG_LAST << 0)

struct wg_transform
{
    struct wg_transform_attrs attrs;

    GstElement *container;
    GstAllocator *allocator;
    GstPad *my_src, *my_sink;
    GstSegment segment;
    GstQuery *drain_query;

    GstAtomicQueue *input_queue;
    GstElement *video_flip;
    MFVideoInfo input_info;

    GstAtomicQueue *output_queue;
    GstSample *output_sample;
    bool output_caps_changed;
    GstCaps *desired_caps;
    GstCaps *output_caps;
};

static struct wg_transform *get_transform(wg_transform_t trans)
{
    return (struct wg_transform *)(ULONG_PTR)trans;
}

static void align_video_info_planes(gsize plane_align, GstVideoInfo *info, GstVideoAlignment *align)
{
    gst_video_alignment_reset(align);

    align->padding_right = ((plane_align + 1) - (info->width & plane_align)) & plane_align;
    align->padding_bottom = ((plane_align + 1) - (info->height & plane_align)) & plane_align;
    align->stride_align[0] = plane_align;
    align->stride_align[1] = plane_align;
    align->stride_align[2] = plane_align;
    align->stride_align[3] = plane_align;

    gst_video_info_align(info, align);
}

typedef struct
{
    GstVideoBufferPool parent;
    GstVideoInfo info;
} WgVideoBufferPool;

typedef struct
{
    GstVideoBufferPoolClass parent_class;
} WgVideoBufferPoolClass;

G_DEFINE_TYPE(WgVideoBufferPool, wg_video_buffer_pool, GST_TYPE_VIDEO_BUFFER_POOL);

static void wg_video_buffer_pool_init(WgVideoBufferPool *pool)
{
}

static void wg_video_buffer_pool_class_init(WgVideoBufferPoolClass *klass)
{
}

static WgVideoBufferPool *wg_video_buffer_pool_create(GstCaps *caps, gsize plane_align,
        GstAllocator *allocator, GstVideoAlignment *align)
{
    WgVideoBufferPool *pool;
    GstStructure *config;

    if (!(pool = g_object_new(wg_video_buffer_pool_get_type(), NULL)))
        return NULL;

    gst_video_info_from_caps(&pool->info, caps);
    align_video_info_planes(plane_align, &pool->info, align);

    if (!(config = gst_buffer_pool_get_config(GST_BUFFER_POOL(pool))))
        GST_ERROR("Failed to get %"GST_PTR_FORMAT" config.", pool);
    else
    {
        gst_buffer_pool_config_add_option(config, GST_BUFFER_POOL_OPTION_VIDEO_META);
        gst_buffer_pool_config_add_option(config, GST_BUFFER_POOL_OPTION_VIDEO_ALIGNMENT);
        gst_buffer_pool_config_set_video_alignment(config, align);

        gst_buffer_pool_config_set_params(config, caps, pool->info.size, 0, 0);
        gst_buffer_pool_config_set_allocator(config, allocator, NULL);
        if (!gst_buffer_pool_set_config(GST_BUFFER_POOL(pool), config))
            GST_ERROR("Failed to set %"GST_PTR_FORMAT" config.", pool);
    }

    GST_INFO("Created %"GST_PTR_FORMAT, pool);
    return pool;
}

static GstFlowReturn transform_sink_chain_cb(GstPad *pad, GstObject *parent, GstBuffer *buffer)
{
    struct wg_transform *transform = gst_pad_get_element_private(pad);
    GstSample *sample;

    GST_LOG("transform %p, %"GST_PTR_FORMAT, transform, buffer);

    if (!(sample = gst_sample_new(buffer, transform->output_caps, NULL, NULL)))
    {
        GST_ERROR("Failed to allocate transform %p output sample.", transform);
        gst_buffer_unref(buffer);
        return GST_FLOW_ERROR;
    }

    if (transform->output_caps_changed && transform->attrs.allow_format_change)
        GST_MINI_OBJECT_FLAG_SET(sample, GST_SAMPLE_FLAG_WG_CAPS_CHANGED);
    transform->output_caps_changed = false;

    gst_atomic_queue_push(transform->output_queue, sample);
    gst_buffer_unref(buffer);
    return GST_FLOW_OK;
}

static gboolean transform_src_query_latency(struct wg_transform *transform, GstQuery *query)
{
    GST_LOG("transform %p, %"GST_PTR_FORMAT, transform, query);
    gst_query_set_latency(query, transform->attrs.low_latency, 0, 0);
    return true;
}

static gboolean transform_src_query_cb(GstPad *pad, GstObject *parent, GstQuery *query)
{
    struct wg_transform *transform = gst_pad_get_element_private(pad);

    switch (query->type)
    {
    case GST_QUERY_LATENCY:
        return transform_src_query_latency(transform, query);
    default:
        GST_TRACE("transform %p, ignoring %"GST_PTR_FORMAT, transform, query);
        return gst_pad_query_default(pad, parent, query);
    }
}

static gboolean transform_sink_query_allocation(struct wg_transform *transform, GstQuery *query)
{
    WgVideoBufferPool *pool;
    GstVideoAlignment align;
    const char *mime_type;
    GstStructure *params;
    gboolean needs_pool;
    GstCaps *caps;

    GST_LOG("transform %p, %"GST_PTR_FORMAT, transform, query);

    gst_query_parse_allocation(query, &caps, &needs_pool);

    mime_type = gst_structure_get_name(gst_caps_get_structure(caps, 0));
    if (strcmp(mime_type, "video/x-raw") || !needs_pool)
        return false;

    if (!(pool = wg_video_buffer_pool_create(caps, transform->attrs.output_plane_align,
            transform->allocator, &align)))
        return false;

    if ((params = gst_structure_new("video-meta",
            "padding-top", G_TYPE_UINT, align.padding_top,
            "padding-bottom", G_TYPE_UINT, align.padding_bottom,
            "padding-left", G_TYPE_UINT, align.padding_left,
            "padding-right", G_TYPE_UINT, align.padding_right,
            NULL)))
    {
        gst_query_add_allocation_meta(query, GST_VIDEO_META_API_TYPE, params);
        gst_structure_free(params);
    }

    /* Prevent pool reconfiguration, we don't want another alignment. */
    if (!gst_buffer_pool_set_active(GST_BUFFER_POOL(pool), true))
        GST_ERROR("%"GST_PTR_FORMAT" failed to activate.", pool);

    gst_query_add_allocation_pool(query, GST_BUFFER_POOL(pool), pool->info.size, 0, 0);
    gst_query_add_allocation_param(query, transform->allocator, NULL);

    GST_INFO("Proposing %"GST_PTR_FORMAT", buffer size %#zx, %"GST_PTR_FORMAT", for %"GST_PTR_FORMAT,
            pool, pool->info.size, transform->allocator, query);

    g_object_unref(pool);
    return true;
}

static void caps_remove_field(GstCaps *caps, const char *field)
{
    guint i;

    for (i = 0; i < gst_caps_get_size(caps); ++i)
    {
        GstStructure *structure = gst_caps_get_structure(caps, i);
        gst_structure_remove_fields(structure, field, NULL);
    }
}

static GstCaps *caps_strip_fields(GstCaps *caps, bool strip_size)
{
    if (stream_type_from_caps(caps) != GST_STREAM_TYPE_VIDEO)
        return gst_caps_ref(caps);

    if ((caps = gst_caps_copy(caps)))
    {
        if (strip_size)
        {
            caps_remove_field(caps, "width");
            caps_remove_field(caps, "height");
        }

        /* strip fields which we do not support and could cause pipeline failure or spurious format changes */
        caps_remove_field(caps, "framerate");
        caps_remove_field(caps, "colorimetry");
        caps_remove_field(caps, "chroma-site");
        caps_remove_field(caps, "interlace-mode");
        caps_remove_field(caps, "pixel-aspect-ratio");
    }

    return caps;
}

static gboolean transform_sink_query_caps(struct wg_transform *transform, GstQuery *query)
{
    GstCaps *caps, *filter, *temp;
    bool strip_size = false;

    GST_LOG("transform %p, %"GST_PTR_FORMAT, transform, query);

    gst_query_parse_caps(query, &filter);
    if (filter && gst_structure_has_field(gst_caps_get_structure(filter, 0), "width"))
        strip_size = transform->attrs.allow_format_change;

    if (!(caps = caps_strip_fields(transform->desired_caps, strip_size)))
        return false;

    if (filter)
    {
        temp = gst_caps_intersect(caps, filter);
        gst_caps_unref(caps);
        caps = temp;
    }

    GST_INFO("Returning caps %" GST_PTR_FORMAT, caps);

    gst_query_set_caps_result(query, caps);
    gst_caps_unref(caps);
    return true;
}

static gboolean transform_sink_query_cb(GstPad *pad, GstObject *parent, GstQuery *query)
{
    struct wg_transform *transform = gst_pad_get_element_private(pad);

    switch (query->type)
    {
    case GST_QUERY_ALLOCATION:
        if (transform_sink_query_allocation(transform, query))
            return true;
        break;
    case GST_QUERY_CAPS:
        if (transform_sink_query_caps(transform, query))
            return true;
        break;
    default:
        break;
    }

    GST_TRACE("transform %p, ignoring %"GST_PTR_FORMAT, transform, query);
    return gst_pad_query_default(pad, parent, query);
}

static void transform_sink_event_caps(struct wg_transform *transform, GstEvent *event)
{
    GstCaps *caps;

    GST_LOG("transform %p, %"GST_PTR_FORMAT, transform, event);

    gst_event_parse_caps(event, &caps);

    transform->output_caps_changed = true;
    gst_caps_unref(transform->desired_caps);
    transform->desired_caps = gst_caps_ref(caps);
    gst_caps_unref(transform->output_caps);
    transform->output_caps = gst_caps_ref(caps);
}

static gboolean transform_sink_event_cb(GstPad *pad, GstObject *parent, GstEvent *event)
{
    struct wg_transform *transform = gst_pad_get_element_private(pad);

    switch (event->type)
    {
    case GST_EVENT_CAPS:
        transform_sink_event_caps(transform, event);
        break;
    default:
        GST_TRACE("transform %p, ignoring %"GST_PTR_FORMAT, transform, event);
        break;
    }

    gst_event_unref(event);
    return TRUE;
}

NTSTATUS wg_transform_destroy(void *args)
{
    struct wg_transform *transform = get_transform(*(wg_transform_t *)args);
    GstSample *sample;
    GstBuffer *buffer;

    while ((buffer = gst_atomic_queue_pop(transform->input_queue)))
        gst_buffer_unref(buffer);
    gst_atomic_queue_unref(transform->input_queue);

    gst_element_set_state(transform->container, GST_STATE_NULL);

    if (transform->output_sample)
        gst_sample_unref(transform->output_sample);
    while ((sample = gst_atomic_queue_pop(transform->output_queue)))
        gst_sample_unref(sample);

    wg_allocator_destroy(transform->allocator);
    g_object_unref(transform->container);
    g_object_unref(transform->my_sink);
    g_object_unref(transform->my_src);
    gst_query_unref(transform->drain_query);
    gst_caps_unref(transform->desired_caps);
    gst_caps_unref(transform->output_caps);
    gst_atomic_queue_unref(transform->output_queue);
    free(transform);

    return STATUS_SUCCESS;
}

static GstCaps *transform_get_parsed_caps(GstCaps *caps, const char *media_type)
{
    GstStructure *structure = gst_caps_get_structure(caps, 0);
    GstCaps *parsed_caps;
    gint value;

    if (!(parsed_caps = gst_caps_new_empty_simple(media_type)))
        return NULL;

    if (gst_structure_get_int(structure, "mpegversion", &value))
    {
        if (value == 4)
            gst_caps_set_simple(parsed_caps, "framed", G_TYPE_BOOLEAN, true, "mpegversion", G_TYPE_INT, 4, NULL);
        else
        {
            gst_caps_set_simple(parsed_caps, "parsed", G_TYPE_BOOLEAN, true, "mpegversion", G_TYPE_INT, value, NULL);
            if (gst_structure_get_int(structure, "layer", &value))
                gst_caps_set_simple(parsed_caps, "layer", G_TYPE_INT, value, NULL);
        }
    }
    else if (gst_structure_get_int(structure, "wmaversion", &value))
        gst_caps_set_simple(parsed_caps, "parsed", G_TYPE_BOOLEAN, true, "wmaversion", G_TYPE_INT, value, NULL);
    else if (gst_structure_get_int(structure, "wmvversion", &value))
        gst_caps_set_simple(parsed_caps, "parsed", G_TYPE_BOOLEAN, true, "wmvversion", G_TYPE_INT, value, NULL);
    else
        gst_caps_set_simple(parsed_caps, "parsed", G_TYPE_BOOLEAN, true, NULL);

    return parsed_caps;
}

NTSTATUS wg_transform_create(void *args)
{
    struct wg_transform_create_params *params = args;
    GstElement *first = NULL, *last = NULL, *element;
    GstCaps *sink_caps = NULL, *src_caps = NULL, *parsed_caps = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    const gchar *input_mime, *output_mime;
    GstPadTemplate *template = NULL;
    struct wg_transform *transform;
    MFVideoInfo output_info = {0};
    GstEvent *event;

    if (!(transform = calloc(1, sizeof(*transform))))
        return STATUS_NO_MEMORY;
    if (!(transform->container = gst_bin_new("wg_transform")))
        goto out;
    if (!(transform->input_queue = gst_atomic_queue_new(8)))
        goto out;
    if (!(transform->output_queue = gst_atomic_queue_new(8)))
        goto out;
    if (!(transform->drain_query = gst_query_new_drain()))
        goto out;
    if (!(transform->allocator = wg_allocator_create()))
        goto out;
    transform->attrs = params->attrs;

    if (IsEqualGUID(&params->input_type.major, &MFMediaType_Video))
        transform->input_info = params->input_type.u.video->videoInfo;
    if (IsEqualGUID(&params->output_type.major, &MFMediaType_Video))
        output_info = params->output_type.u.video->videoInfo;

    if (!(src_caps = caps_from_media_type(&params->input_type)))
        goto out;
    if (!(template = gst_pad_template_new("src", GST_PAD_SRC, GST_PAD_ALWAYS, src_caps)))
        goto out;
    transform->my_src = gst_pad_new_from_template(template, "src");
    g_object_unref(template);
    if (!transform->my_src)
        goto out;

    GST_INFO("transform %p input caps %"GST_PTR_FORMAT, transform, src_caps);

    gst_pad_set_element_private(transform->my_src, transform);
    gst_pad_set_query_function(transform->my_src, transform_src_query_cb);

    if (!(transform->output_caps = caps_from_media_type(&params->output_type)))
        goto out;
    transform->desired_caps = gst_caps_ref(transform->output_caps);
    if (!(template = gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, transform->output_caps)))
        goto out;
    transform->my_sink = gst_pad_new_from_template(template, "sink");
    g_object_unref(template);
    if (!transform->my_sink)
        goto out;

    GST_INFO("transform %p output caps %"GST_PTR_FORMAT, transform, transform->output_caps);

    gst_pad_set_element_private(transform->my_sink, transform);
    gst_pad_set_event_function(transform->my_sink, transform_sink_event_cb);
    gst_pad_set_query_function(transform->my_sink, transform_sink_query_cb);
    gst_pad_set_chain_function(transform->my_sink, transform_sink_chain_cb);

    input_mime = gst_structure_get_name(gst_caps_get_structure(src_caps, 0));
    if (!(parsed_caps = transform_get_parsed_caps(src_caps, input_mime)))
        goto out;

    /* Since we append conversion elements, we don't want to filter decoders
     * based on the actual output caps now. Matching decoders with the
     * raw output media type should be enough.
     */
    output_mime = gst_structure_get_name(gst_caps_get_structure(transform->output_caps, 0));
    if (!(sink_caps = gst_caps_new_empty_simple(output_mime)))
        goto out;

    if (strcmp(input_mime, "audio/x-raw") && strcmp(input_mime, "video/x-raw"))
    {
        if ((element = find_element(GST_ELEMENT_FACTORY_TYPE_PARSER, src_caps, parsed_caps))
                && !append_element(transform->container, element, &first, &last))
            goto out;
        else if (!element)
        {
            gst_caps_unref(parsed_caps);
            parsed_caps = gst_caps_ref(src_caps);
        }

        if (!(element = find_element(GST_ELEMENT_FACTORY_TYPE_DECODER, parsed_caps, sink_caps))
                || !append_element(transform->container, element, &first, &last))
            goto out;
    }

    if (g_str_has_prefix(output_mime, "audio/"))
    {
        if (strcmp(output_mime, "audio/x-raw"))
        {
            GST_FIXME("output caps %"GST_PTR_FORMAT" not implemented!", transform->output_caps);
            goto out;
        }
        else
        {
            /* The MF audio decoder transforms allow decoding to various formats
             * as well as resampling the audio at the same time, whereas
             * GStreamer decoder plugins usually only support decoding to a
             * single format and at the original rate.
             *
             * The WMA decoder transform also has output samples interleaved on
             * Windows, whereas GStreamer avdec_wmav2 output uses
             * non-interleaved format.
             */
            if (!(element = create_element("audioconvert", "base"))
                    || !append_element(transform->container, element, &first, &last))
                goto out;
            if (!(element = create_element("audioresample", "base"))
                    || !append_element(transform->container, element, &first, &last))
                goto out;
        }
    }

    if (g_str_has_prefix(output_mime, "video/"))
    {
        if (strcmp(output_mime, "video/x-raw"))
        {
            GST_FIXME("output caps %"GST_PTR_FORMAT" not implemented!", transform->output_caps);
            goto out;
        }
        else
        {
            if (!(element = create_element("videoconvert", "base"))
                    || !append_element(transform->container, element, &first, &last))
                goto out;
            if (!(transform->video_flip = create_element("videoflip", "base"))
                    || !append_element(transform->container, transform->video_flip, &first, &last))
                goto out;

            if ((transform->input_info.VideoFlags ^ output_info.VideoFlags) & MFVideoFlag_BottomUpLinearRep)
                gst_util_set_object_arg(G_OBJECT(transform->video_flip), "method", "vertical-flip");
            if (!(element = create_element("videoconvert", "base"))
                    || !append_element(transform->container, element, &first, &last))
                goto out;
            /* Let GStreamer choose a default number of threads. */
            gst_util_set_object_arg(G_OBJECT(element), "n-threads", "0");
        }
    }

    if (!link_src_to_element(transform->my_src, first))
        goto out;
    if (!link_element_to_sink(last, transform->my_sink))
        goto out;
    if (!gst_pad_set_active(transform->my_sink, 1))
        goto out;
    if (!gst_pad_set_active(transform->my_src, 1))
        goto out;

    gst_element_set_state(transform->container, GST_STATE_PAUSED);
    if (!gst_element_get_state(transform->container, NULL, NULL, -1))
        goto out;

    if (!(event = gst_event_new_stream_start("stream"))
            || !push_event(transform->my_src, event))
        goto out;
    if (!(event = gst_event_new_caps(src_caps))
            || !push_event(transform->my_src, event))
        goto out;

    /* We need to use GST_FORMAT_TIME here because it's the only format
     * some elements such avdec_wmav2 correctly support. */
    gst_segment_init(&transform->segment, GST_FORMAT_TIME);
    transform->segment.start = 0;
    transform->segment.stop = -1;
    if (!(event = gst_event_new_segment(&transform->segment))
            || !push_event(transform->my_src, event))
        goto out;

    gst_caps_unref(parsed_caps);
    gst_caps_unref(src_caps);
    gst_caps_unref(sink_caps);

    GST_INFO("Created winegstreamer transform %p.", transform);
    params->transform = (wg_transform_t)(ULONG_PTR)transform;
    return STATUS_SUCCESS;

out:
    if (transform->my_sink)
        gst_object_unref(transform->my_sink);
    if (transform->desired_caps)
        gst_caps_unref(transform->desired_caps);
    if (transform->output_caps)
        gst_caps_unref(transform->output_caps);
    if (transform->my_src)
        gst_object_unref(transform->my_src);
    if (src_caps)
        gst_caps_unref(src_caps);
    if (parsed_caps)
        gst_caps_unref(parsed_caps);
    if (sink_caps)
        gst_caps_unref(sink_caps);
    if (transform->allocator)
        wg_allocator_destroy(transform->allocator);
    if (transform->drain_query)
        gst_query_unref(transform->drain_query);
    if (transform->output_queue)
        gst_atomic_queue_unref(transform->output_queue);
    if (transform->input_queue)
        gst_atomic_queue_unref(transform->input_queue);
    if (transform->container)
    {
        gst_element_set_state(transform->container, GST_STATE_NULL);
        gst_object_unref(transform->container);
    }
    free(transform);
    GST_ERROR("Failed to create winegstreamer transform.");
    return status;
}

NTSTATUS wg_transform_get_output_type(void *args)
{
    struct wg_transform_get_output_type_params *params = args;
    struct wg_transform *transform = get_transform(params->transform);
    GstCaps *output_caps;

    if (transform->output_sample)
        output_caps = gst_sample_get_caps(transform->output_sample);
    else
        output_caps = transform->output_caps;

    GST_INFO("transform %p output caps %"GST_PTR_FORMAT, transform, output_caps);

    return caps_to_media_type(output_caps, &params->media_type, transform->attrs.output_plane_align);
}

NTSTATUS wg_transform_set_output_type(void *args)
{
    struct wg_transform_set_output_type_params *params = args;
    struct wg_transform *transform = get_transform(params->transform);
    MFVideoInfo output_info = {0};
    GstCaps *caps, *stripped;
    GstSample *sample;

    if (IsEqualGUID(&params->media_type.major, &MFMediaType_Video))
        output_info = params->media_type.u.video->videoInfo;

    if (!(caps = caps_from_media_type(&params->media_type)))
    {
        GST_ERROR("Failed to convert media type to caps.");
        return STATUS_UNSUCCESSFUL;
    }

    GST_INFO("transform %p output caps %"GST_PTR_FORMAT, transform, caps);

    stripped = caps_strip_fields(caps, transform->attrs.allow_format_change);
    if (gst_caps_is_always_compatible(transform->output_caps, stripped))
    {
        gst_caps_unref(stripped);
        gst_caps_unref(caps);
        return STATUS_SUCCESS;
    }
    gst_caps_unref(stripped);

    if (!gst_pad_peer_query(transform->my_src, transform->drain_query))
    {
        GST_ERROR("Failed to drain transform %p.", transform);
        return STATUS_UNSUCCESSFUL;
    }

    gst_caps_unref(transform->desired_caps);
    transform->desired_caps = caps;

    if (transform->video_flip)
    {
        const char *value;

        if ((transform->input_info.VideoFlags ^ output_info.VideoFlags) & MFVideoFlag_BottomUpLinearRep)
            value = "vertical-flip";
        else
            value = "none";
        gst_util_set_object_arg(G_OBJECT(transform->video_flip), "method", value);
    }
    if (!push_event(transform->my_sink, gst_event_new_reconfigure()))
    {
        GST_ERROR("Failed to reconfigure transform %p.", transform);
        return STATUS_UNSUCCESSFUL;
    }

    GST_INFO("Configured new caps %" GST_PTR_FORMAT ".", caps);

    /* Ideally and to be fully compatible with native transform, the queued
     * output buffers will need to be converted to the new output format and
     * kept queued.
     */
    if (transform->output_sample)
        gst_sample_unref(transform->output_sample);
    while ((sample = gst_atomic_queue_pop(transform->output_queue)))
        gst_sample_unref(sample);
    transform->output_sample = NULL;

    return STATUS_SUCCESS;
}

static void wg_sample_free_notify(void *arg)
{
    struct wg_sample *sample = arg;
    GST_DEBUG("Releasing wg_sample %p", sample);
    InterlockedDecrement(&sample->refcount);
}

NTSTATUS wg_transform_push_data(void *args)
{
    struct wg_transform_push_data_params *params = args;
    struct wg_transform *transform = get_transform(params->transform);
    struct wg_sample *sample = params->sample;
    GstBuffer *buffer;
    guint length;

    length = gst_atomic_queue_length(transform->input_queue);
    if (length >= transform->attrs.input_queue_length + 1)
    {
        GST_INFO("Refusing %u bytes, %u buffers already queued", sample->size, length);
        params->result = MF_E_NOTACCEPTING;
        return STATUS_SUCCESS;
    }

    if (!(buffer = gst_buffer_new_wrapped_full(GST_MEMORY_FLAG_READONLY, wg_sample_data(sample), sample->max_size,
            0, sample->size, sample, wg_sample_free_notify)))
    {
        GST_ERROR("Failed to allocate input buffer");
        return STATUS_NO_MEMORY;
    }
    else
    {
        InterlockedIncrement(&sample->refcount);
        GST_INFO("Wrapped %u/%u bytes from sample %p to %"GST_PTR_FORMAT, sample->size, sample->max_size, sample, buffer);
    }

    if (sample->flags & WG_SAMPLE_FLAG_HAS_PTS)
        GST_BUFFER_PTS(buffer) = sample->pts * 100;
    if (sample->flags & WG_SAMPLE_FLAG_HAS_DURATION)
        GST_BUFFER_DURATION(buffer) = sample->duration * 100;
    if (!(sample->flags & WG_SAMPLE_FLAG_SYNC_POINT))
        GST_BUFFER_FLAG_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT);
    if (sample->flags & WG_SAMPLE_FLAG_DISCONTINUITY)
        GST_BUFFER_FLAG_SET(buffer, GST_BUFFER_FLAG_DISCONT);
    gst_atomic_queue_push(transform->input_queue, buffer);

    params->result = S_OK;
    return STATUS_SUCCESS;
}

static NTSTATUS copy_video_buffer(GstBuffer *buffer, const GstVideoInfo *src_video_info,
        const GstVideoInfo *dst_video_info, struct wg_sample *sample, gsize *total_size)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    GstVideoFrame src_frame, dst_frame;
    GstBuffer *dst_buffer;

    if (sample->max_size < dst_video_info->size)
    {
        GST_ERROR("Output buffer is too small.");
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!(dst_buffer = gst_buffer_new_wrapped_full(0, wg_sample_data(sample), sample->max_size,
            0, sample->max_size, 0, NULL)))
    {
        GST_ERROR("Failed to wrap wg_sample into GstBuffer");
        return STATUS_UNSUCCESSFUL;
    }
    gst_buffer_set_size(dst_buffer, dst_video_info->size);
    *total_size = sample->size = dst_video_info->size;

    if (!gst_video_frame_map(&src_frame, src_video_info, buffer, GST_MAP_READ))
        GST_ERROR("Failed to map source frame.");
    else
    {
        if (!gst_video_frame_map(&dst_frame, dst_video_info, dst_buffer, GST_MAP_WRITE))
            GST_ERROR("Failed to map destination frame.");
        else
        {
            if (gst_video_frame_copy(&dst_frame, &src_frame))
                status = STATUS_SUCCESS;
            else
                GST_ERROR("Failed to copy video frame.");
            gst_video_frame_unmap(&dst_frame);
        }
        gst_video_frame_unmap(&src_frame);
    }

    gst_buffer_unref(dst_buffer);
    return status;
}

static NTSTATUS copy_buffer(GstBuffer *buffer, struct wg_sample *sample, gsize *total_size)
{
    GstMapInfo info;

    if (!gst_buffer_map(buffer, &info, GST_MAP_READ))
        return STATUS_UNSUCCESSFUL;

    if (sample->max_size >= info.size)
        sample->size = info.size;
    else
    {
        sample->flags |= WG_SAMPLE_FLAG_INCOMPLETE;
        sample->size = sample->max_size;
    }

    memcpy(wg_sample_data(sample), info.data, sample->size);
    gst_buffer_unmap(buffer, &info);

    if (sample->flags & WG_SAMPLE_FLAG_INCOMPLETE)
        gst_buffer_resize(buffer, sample->size, -1);

    *total_size = info.size;
    return STATUS_SUCCESS;
}

static void set_sample_flags_from_buffer(struct wg_sample *sample, GstBuffer *buffer, gsize total_size)
{
    if (GST_BUFFER_PTS_IS_VALID(buffer))
    {
        sample->flags |= WG_SAMPLE_FLAG_HAS_PTS;
        sample->pts = GST_BUFFER_PTS(buffer) / 100;
    }
    if (GST_BUFFER_DURATION_IS_VALID(buffer))
    {
        GstClockTime duration = GST_BUFFER_DURATION(buffer) / 100;

        duration = (duration * sample->size) / total_size;
        GST_BUFFER_DURATION(buffer) -= duration * 100;
        if (GST_BUFFER_PTS_IS_VALID(buffer))
            GST_BUFFER_PTS(buffer) += duration * 100;

        sample->flags |= WG_SAMPLE_FLAG_HAS_DURATION;
        sample->duration = duration;
    }
    if (!GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DELTA_UNIT))
        sample->flags |= WG_SAMPLE_FLAG_SYNC_POINT;
    if (GST_BUFFER_FLAG_IS_SET(buffer, GST_BUFFER_FLAG_DISCONT))
        sample->flags |= WG_SAMPLE_FLAG_DISCONTINUITY;
}

static bool sample_needs_buffer_copy(struct wg_sample *sample, GstBuffer *buffer, gsize *total_size)
{
    GstMapInfo info;
    bool needs_copy;

    if (!gst_buffer_map(buffer, &info, GST_MAP_READ))
    {
        GST_ERROR("Failed to map buffer %"GST_PTR_FORMAT, buffer);
        sample->size = 0;
        return STATUS_UNSUCCESSFUL;
    }
    needs_copy = info.data != wg_sample_data(sample);
    *total_size = sample->size = info.size;
    gst_buffer_unmap(buffer, &info);

    return needs_copy;
}

static NTSTATUS read_transform_output_video(struct wg_sample *sample, GstBuffer *buffer,
        const GstVideoInfo *src_video_info, const GstVideoInfo *dst_video_info)
{
    gsize total_size;
    NTSTATUS status;
    bool needs_copy;

    if (!(needs_copy = sample_needs_buffer_copy(sample, buffer, &total_size)))
        status = STATUS_SUCCESS;
    else
        status = copy_video_buffer(buffer, src_video_info, dst_video_info, sample, &total_size);

    if (status)
    {
        GST_ERROR("Failed to copy buffer %"GST_PTR_FORMAT, buffer);
        sample->size = 0;
        return status;
    }

    set_sample_flags_from_buffer(sample, buffer, total_size);

    if (needs_copy)
        GST_WARNING("Copied %u bytes, sample %p, flags %#x", sample->size, sample, sample->flags);
    else if (sample->flags & WG_SAMPLE_FLAG_INCOMPLETE)
        GST_ERROR("Partial read %u bytes, sample %p, flags %#x", sample->size, sample, sample->flags);
    else
        GST_INFO("Read %u bytes, sample %p, flags %#x", sample->size, sample, sample->flags);

    return STATUS_SUCCESS;
}

static NTSTATUS read_transform_output(struct wg_sample *sample, GstBuffer *buffer)
{
    gsize total_size;
    NTSTATUS status;
    bool needs_copy;

    if (!(needs_copy = sample_needs_buffer_copy(sample, buffer, &total_size)))
        status = STATUS_SUCCESS;
    else
        status = copy_buffer(buffer, sample, &total_size);

    if (status)
    {
        GST_ERROR("Failed to copy buffer %"GST_PTR_FORMAT, buffer);
        sample->size = 0;
        return status;
    }

    set_sample_flags_from_buffer(sample, buffer, total_size);

    if (needs_copy)
        GST_INFO("Copied %u bytes, sample %p, flags %#x", sample->size, sample, sample->flags);
    else if (sample->flags & WG_SAMPLE_FLAG_INCOMPLETE)
        GST_ERROR("Partial read %u bytes, sample %p, flags %#x", sample->size, sample, sample->flags);
    else
        GST_INFO("Read %u bytes, sample %p, flags %#x", sample->size, sample, sample->flags);

    return STATUS_SUCCESS;
}

static bool get_transform_output(struct wg_transform *transform, struct wg_sample *sample)
{
    GstBuffer *input_buffer;
    GstFlowReturn ret;

    wg_allocator_provide_sample(transform->allocator, sample);

    while (!(transform->output_sample = gst_atomic_queue_pop(transform->output_queue))
            && (input_buffer = gst_atomic_queue_pop(transform->input_queue)))
    {
        if ((ret = gst_pad_push(transform->my_src, input_buffer)))
            GST_WARNING("Failed to push transform input, error %d", ret);
    }

    /* Remove the sample so the allocator cannot use it */
    wg_allocator_provide_sample(transform->allocator, NULL);

    return !!transform->output_sample;
}

NTSTATUS wg_transform_read_data(void *args)
{
    struct wg_transform_read_data_params *params = args;
    struct wg_transform *transform = get_transform(params->transform);
    GstVideoInfo src_video_info, dst_video_info;
    struct wg_sample *sample = params->sample;
    GstVideoAlignment align = {0};
    GstBuffer *output_buffer;
    const char *output_mime;
    GstCaps *output_caps;
    bool discard_data;
    NTSTATUS status;

    if (!transform->output_sample && !get_transform_output(transform, sample))
    {
        sample->size = 0;
        params->result = MF_E_TRANSFORM_NEED_MORE_INPUT;
        GST_INFO("Cannot read %u bytes, no output available", sample->max_size);
        wg_allocator_release_sample(transform->allocator, sample, false);
        return STATUS_SUCCESS;
    }

    output_buffer = gst_sample_get_buffer(transform->output_sample);
    output_caps = gst_sample_get_caps(transform->output_sample);
    output_mime = gst_structure_get_name(gst_caps_get_structure(output_caps, 0));

    if (!strcmp(output_mime, "video/x-raw"))
    {
        gsize plane_align = transform->attrs.output_plane_align;

        if (!gst_video_info_from_caps(&src_video_info, output_caps))
            GST_ERROR("Failed to get video info from %"GST_PTR_FORMAT, output_caps);
        dst_video_info = src_video_info;

        /* set the desired output buffer alignment on the dest video info */
        align_video_info_planes(plane_align, &dst_video_info, &align);
    }

    if (GST_MINI_OBJECT_FLAG_IS_SET(transform->output_sample, GST_SAMPLE_FLAG_WG_CAPS_CHANGED))
    {
        GST_MINI_OBJECT_FLAG_UNSET(transform->output_sample, GST_SAMPLE_FLAG_WG_CAPS_CHANGED);
        params->result = MF_E_TRANSFORM_STREAM_CHANGE;
        GST_INFO("Format changed detected, returning no output");
        wg_allocator_release_sample(transform->allocator, sample, false);
        return STATUS_SUCCESS;
    }

    if (!strcmp(output_mime, "video/x-raw"))
        status = read_transform_output_video(sample, output_buffer,
                &src_video_info, &dst_video_info);
    else
        status = read_transform_output(sample, output_buffer);

    if (status)
    {
        wg_allocator_release_sample(transform->allocator, sample, false);
        return status;
    }

    if (sample->flags & WG_SAMPLE_FLAG_INCOMPLETE)
        discard_data = false;
    else
    {
        /* Taint the buffer memory to make sure it cannot be reused by the buffer pool,
         * for the pool to always requests new memory from the allocator, and so we can
         * then always provide output sample memory to achieve zero-copy.
         *
         * However, some decoder keep a reference on the buffer they passed downstream,
         * to re-use it later. In this case, it will not be possible to do zero-copy,
         * and we should copy the data back to the buffer and leave it unchanged.
         *
         * Some other plugins make assumptions that the returned buffer will always have
         * at least one memory attached, we cannot just remove it and need to replace the
         * memory instead.
         */
        if ((discard_data = gst_buffer_is_writable(output_buffer)))
            gst_buffer_replace_all_memory(output_buffer, gst_allocator_alloc(NULL, 0, NULL));

        gst_sample_unref(transform->output_sample);
        transform->output_sample = NULL;
    }

    params->result = S_OK;
    wg_allocator_release_sample(transform->allocator, sample, discard_data);
    return STATUS_SUCCESS;
}

NTSTATUS wg_transform_get_status(void *args)
{
    struct wg_transform_get_status_params *params = args;
    struct wg_transform *transform = get_transform(params->transform);

    params->accepts_input = gst_atomic_queue_length(transform->input_queue) < transform->attrs.input_queue_length + 1;
    return STATUS_SUCCESS;
}

NTSTATUS wg_transform_drain(void *args)
{
    struct wg_transform *transform = get_transform(*(wg_transform_t *)args);
    GstBuffer *input_buffer;
    GstFlowReturn ret;
    GstEvent *event;

    GST_LOG("transform %p", transform);

    while ((input_buffer = gst_atomic_queue_pop(transform->input_queue)))
    {
        if ((ret = gst_pad_push(transform->my_src, input_buffer)))
            GST_WARNING("Failed to push transform input, error %d", ret);
    }

    if (!(event = gst_event_new_segment_done(GST_FORMAT_TIME, -1))
            || !push_event(transform->my_src, event))
        goto error;
    if (!(event = gst_event_new_eos())
            || !push_event(transform->my_src, event))
        goto error;
    if (!(event = gst_event_new_stream_start("stream"))
            || !push_event(transform->my_src, event))
        goto error;
    if (!(event = gst_event_new_segment(&transform->segment))
            || !push_event(transform->my_src, event))
        goto error;

    return STATUS_SUCCESS;

error:
    GST_ERROR("Failed to drain transform %p.", transform);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS wg_transform_flush(void *args)
{
    struct wg_transform *transform = get_transform(*(wg_transform_t *)args);
    GstBuffer *input_buffer;
    GstSample *sample;
    NTSTATUS status;

    GST_LOG("transform %p", transform);

    while ((input_buffer = gst_atomic_queue_pop(transform->input_queue)))
        gst_buffer_unref(input_buffer);

    if ((status = wg_transform_drain(args)))
        return status;

    while ((sample = gst_atomic_queue_pop(transform->output_queue)))
        gst_sample_unref(sample);
    if ((sample = transform->output_sample))
        gst_sample_unref(sample);
    transform->output_sample = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS wg_transform_notify_qos(void *args)
{
    const struct wg_transform_notify_qos_params *params = args;
    struct wg_transform *transform = get_transform(params->transform);
    GstClockTimeDiff diff = params->diff * 100;
    GstClockTime stream_time;
    GstEvent *event;

    /* We return timestamps in stream time, i.e. relative to the start of the
     * file (or other medium), but gst_event_new_qos() expects the timestamp in
     * running time. */
    stream_time = gst_segment_to_running_time(&transform->segment, GST_FORMAT_TIME, params->timestamp * 100);
    if (diff < (GstClockTimeDiff)-stream_time)
        diff = -stream_time;
    if (stream_time == -1)
    {
        /* This can happen legitimately if the sample falls outside of the
         * segment bounds. GStreamer elements shouldn't present the sample in
         * that case, but DirectShow doesn't care. */
        GST_LOG("Ignoring QoS event.");
        return S_OK;
    }
    event = gst_event_new_qos(params->underflow ? GST_QOS_TYPE_UNDERFLOW : GST_QOS_TYPE_OVERFLOW, params->proportion, diff, stream_time);
    push_event(transform->my_sink, event);

    return S_OK;
}
