/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <time.h>
#include "xlator.h"
#include "defaults.h"
#include "read-only-common.h"
#include "read-only-mem-types.h"
#include "read-only.h"

gf_lock_t stat_lock;
int32_t can_op = 0;

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        ret = xlator_mem_acct_init (this, gf_read_only_mt_end + 1);
        if (ret)
                gf_log (this->name, GF_LOG_ERROR, "Memory accounting "
                        "initialization failed.");

        return ret;
}


int32_t
worm_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct iatt *buf,
                  dict_t *xdata)
{
        int32_t ret = 0;
        can_op = 1; 
        struct timespec c_ts = {0, 0};
        ret = clock_gettime (CLOCK_REALTIME, &c_ts);

        if (op_errno != 0)
        {
            can_op = 0;
        }
        else if (ret != 0)
        {
            can_op = 0;
        }
        else if(!buf)
        {
            can_op = 0;
        }
        else if( (buf->ia_mtime > 86400) && (c_ts.tv_sec - buf->ia_mtime >= 10) )
        {
            can_op = 0;
        }

        return can_op;
}

static int32_t
worm_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
               int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd, xdata);
        return 0;
}

int32_t
worm_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
           fd_t *fd, dict_t *xdata)
{
        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this) &&
            ((((flags & O_ACCMODE) == O_WRONLY) ||
              ((flags & O_ACCMODE) == O_RDWR)) &&
              !(flags & O_APPEND)))
        {
            local_frame = copy_frame(frame);
            LOCK(&stat_lock);
            STACK_WIND (local_frame, worm_stat_cbk,
                        FIRST_CHILD(this),
                        FIRST_CHILD(this)->fops->stat, loc, xdata);

            FRAME_DESTROY(local_frame);

            if (can_op == 0)
            {
                UNLOCK(&stat_lock);
                STACK_UNWIND_STRICT (open, frame, -1, EROFS, NULL, NULL);
                return 0;
            }
            UNLOCK(&stat_lock);
        }

        STACK_WIND (frame, worm_open_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->open, loc, flags, fd, xdata);
        return 0;
}

int32_t
worm_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset, dict_t *xdata)
{

        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->stat, loc, xdata);

                FRAME_DESTROY(local_frame);
                
                if (can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (truncate, frame, -1, EROFS, NULL, NULL,
                                         xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }

        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                        FIRST_CHILD(this)->fops->truncate, loc, offset,
                        xdata);

    return 0;
}

static int
_check_key_is_zero_filled (dict_t *d, char *k, data_t *v,
                           void *tmp)
{
        if (mem_0filled ((const char *)v->data, v->len)) {
                /* -1 means, no more iterations, treat as 'break' */
                return -1;
        }
        return 0;
}

int32_t
worm_xattrop (call_frame_t *frame, xlator_t *this, loc_t *loc,
            gf_xattrop_flags_t flags, dict_t *dict, dict_t *xdata)
{

        gf_boolean_t allzero = _gf_false;
        int     ret = 0;

        ret = dict_foreach (dict, _check_key_is_zero_filled, NULL);
        if (ret == 0)
                allzero = _gf_true;

        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->stat, loc, xdata);

                FRAME_DESTROY(local_frame);

                if(can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (xattrop, frame, -1, EROFS, NULL, xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }
        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD(this)->fops->xattrop,
                         loc, flags, dict, xdata);
        return 0;
}

int32_t
worm_removexattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                const char *name, dict_t *xdata)
{

        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->stat, loc, xdata);

                FRAME_DESTROY(local_frame);

                if(can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (removexattr, frame, -1, EROFS, xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }
        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD(this)->fops->removexattr, loc,
                         name, xdata);

        return 0;
}

int32_t
worm_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc, int xflag,
           dict_t *xdata)
{
        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->stat, loc, xdata);

                FRAME_DESTROY(local_frame);

                if(can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (unlink, frame, -1, EROFS, NULL, NULL,
                                         xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }

        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD(this)->fops->unlink, loc, xflag,
                         xdata);

        return 0;
}

int32_t
worm_fsyncdir (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t flags,
             dict_t *xdata)
{
        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->fstat, fd, xdata);

                FRAME_DESTROY(local_frame);

                if(can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (fsyncdir, frame, -1, EROFS, xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }

        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD(this)->fops->fsyncdir, fd, flags,
                         xdata);

    return 0;
}

int32_t
worm_rename (call_frame_t *frame, xlator_t *this, loc_t *oldloc, loc_t *newloc,
           dict_t *xdata)
{
        call_frame_t *local_frame;

        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->stat, oldloc, xdata);

                FRAME_DESTROY(local_frame);

                if(can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (rename, frame, -1, EROFS, NULL, NULL, NULL,
                                         NULL, NULL, xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }
        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD(this)->fops->rename, oldloc,
                         newloc, xdata);

        return 0;
}

int
worm_rmdir (call_frame_t *frame, xlator_t *this, loc_t *loc, int flags,
          dict_t *xdata)
{
        call_frame_t *local_frame;
        if (is_readonly_or_worm_enabled (this))
        {
                local_frame = copy_frame(frame);
                LOCK(&stat_lock);
                STACK_WIND (local_frame, worm_stat_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->stat, loc, xdata);
                FRAME_DESTROY(local_frame);
                if(can_op == 0)
                {
                    UNLOCK(&stat_lock);
                    STACK_UNWIND_STRICT (rmdir, frame, -1, EROFS, NULL, NULL,
                                         xdata);
                    return 0;
                }
                UNLOCK(&stat_lock);
        }
        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                         FIRST_CHILD(this)->fops->rmdir, loc, flags,
                         xdata);

        return 0;
}

int32_t
init (xlator_t *this)
{
        int                     ret     = -1;
        read_only_priv_t       *priv    = NULL;

        if (!this->children || this->children->next) {
                gf_log (this->name, GF_LOG_ERROR,
                        "translator not configured with exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        priv = GF_CALLOC (1, sizeof (*priv), gf_read_only_mt_priv_t);
        if (!priv)
                goto out;

        GF_OPTION_INIT ("worm", priv->readonly_or_worm_enabled, bool, out);

        LOCK_INIT(&stat_lock);

        this->private = priv;
        ret = 0;
out:
        return ret;
}

int
reconfigure (xlator_t *this, dict_t *options)
{
        read_only_priv_t  *priv                     = NULL;
        int                ret                      = -1;
        gf_boolean_t       readonly_or_worm_enabled = _gf_false;

        priv = this->private;
        GF_ASSERT (priv);

        GF_OPTION_RECONF ("worm", readonly_or_worm_enabled, options, bool, out);

        priv->readonly_or_worm_enabled = readonly_or_worm_enabled;
        ret = 0;
out:
        gf_log (this->name, GF_LOG_DEBUG, "returning %d", ret);
        return ret;
}

void
fini (xlator_t *this)
{
        read_only_priv_t         *priv    = NULL;

        priv = this->private;
        if (!priv)
                return;

        this->private = NULL;
        GF_FREE (priv);
        LOCK_DESTROY(&stat_lock);

        return;
}

struct xlator_fops fops = {
        .open        = worm_open,

        .unlink      = worm_unlink,
        .rmdir       = worm_rmdir,
        .rename      = worm_rename,
        .truncate    = worm_truncate,
        .removexattr = worm_removexattr,
        .fsyncdir    = worm_fsyncdir,
        .xattrop     = worm_xattrop,
        .inodelk     = ro_inodelk,
        .finodelk    = ro_finodelk,
        .entrylk     = ro_entrylk,
        .fentrylk    = ro_fentrylk,
        .lk          = ro_lk,
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {"worm"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "off",
          .description = "When \"on\", makes a volume get write once read many "
                         " feature. It is turned \"off\" by default."
        },
};

