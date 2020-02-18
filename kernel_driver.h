#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

//Define information about the project and the author
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michelangelo Sarafis");
MODULE_DESCRIPTION("A honeypot made to detect potential system intruders");
MODULE_VERSION("1.0");


//Tail call optimization sometimes messes up 
//return address checks, that are mandatory for this project
//for unwanted recursion avoidance purposes
#pragma GCC optimize("-fno-optimize-sibling-calls")

//The default ftrace hook structure
struct ftrace_hook {
        const char *name;
        void *function;
        void *original;
 
        unsigned long address;
        struct ftrace_ops ops;
};

//Define all the functions to be used on the project
static int __init init_routine(void);
static void __exit exit_routine(void);
static char *usr_to_krnl_strcpy(const char __user *str);
static void send_msg_to_user(const char* message);
static int resolve_hook_address(struct ftrace_hook *hook);
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
static void notrace fh_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct pt_regs *regs);
static void fh_do_sys_open(int dfd, const char __user *filename, int flags, int mode);

//Define the original sys_open to be called
static void (*real_do_sys_open)(int dfd, const char __user *filename, int flags, int mode);

//An ftrace_hook structure instance that will hold
//our sys_open system call hook
struct ftrace_hook ftrace_do_sys_open;

//the path of the file that works as a honeypot
#define FILE_TO_WATCH_PATH "creditcard.txt"

//The multicast group that we
//broadcast messages to on userland
#define NETLINK_GROUP 21

//a socket instance that will hold
//our connection with the userland
static struct sock *nl_sk = NULL;