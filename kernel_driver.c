#include "kernel_driver.h"

static char *usr_to_krnl_strcpy(const char __user *str)
{
        //maximum buffer length we are going to accept
        const size_t max_size = 4096;
        //the variable pointer that will hold our string
	char *kernel_string;
        //the variable that will hold the length of the string
        int strSize;

        //get the length of the string given in userspace
        strSize = strnlen_user(str, max_size);

        //if the function failed (return value is 0),
        if(!strSize)
                return NULL; //return a NULL pointer

        //allocate a space in memory with the size of the string
	kernel_string = kmalloc(strSize, GFP_KERNEL);
	
        //if the allocation failed (return value is 0),
        if (!kernel_string)
		return NULL; //return a NULL pointer

        //copy the buffer from userspace to kernel safely,
        //and if it failed (return value less than zero),
	if (strncpy_from_user(kernel_string, str, strSize) < 0) 
        {
                //free the memory allocated
		kfree(kernel_string);
                //return a NULL pointer
		return NULL;
	}

        //if we got thus far, everything went
        //fine. Just return the pointer of the string
	return kernel_string;
}

static void send_msg_to_user(const char* message)
{
    //initialize the strctures needed
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    //initialize the variables needed
    int messageSize;
    int errorVal;

    //get the size if the message and add one
    //to include the NULL-Termination character
    messageSize = strlen(message) + 1;

    //Create our new SKB and allocate its memory
    skb = nlmsg_new(NLMSG_ALIGN(messageSize + 1), GFP_KERNEL);

    //if skb failed to allocate/initialize
    //(return value is 0),
    if (!skb) 
    {
        //inform the user
        pr_debug("Allocation failure.\n");
        //return the function
        return;
    }

    //Create our message container for our SKB
    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, messageSize + 1, 0);
    //copy the text message to the buffer associated
    //with the container initialized above
    strcpy(nlmsg_data(nlh), message);

    //send the SKB to all clients listening to our multicast-group
    errorVal = nlmsg_multicast(nl_sk, skb, 0, NETLINK_GROUP, GFP_KERNEL);

    //if function failed (return value lower than zero),
    if (errorVal < 0)
        pr_debug("nlmsg_multicast() error: %d\n", errorVal); //inform the user
    else
        pr_debug("Success.\n"); //otherwise everything went fine, inform the user
}

//this is the hooked version of the function
static void fh_do_sys_open(int dfd, const char __user *filename, int flags, int mode)
{
        //copy the user space string to kernel
        char* kernFl = usr_to_krnl_strcpy(filename);

        if(strstr(kernFl, FILE_TO_WATCH_PATH) != NULL)
        {
             //get the id of the user that gave the order
             kuid_t senderUid = current->cred->uid;
             //get the name of the process that requested the file opening
             char* processName = current->comm;
             //get the ID of the process that requested the file opening
             int pid = current->pid;
             //a buffer to concatenate all data together for the userland
             //ATTENTION: Considering that the maximum username length on unix OS is by default 32,
             //this buffer SHOULD NOT overflow. Nevertheless, additional measures should be taken in the future
             char* buffer = kmalloc(4096, GFP_KERNEL);

             //print a debug message that the file was accessed by the specific user
             pr_debug("[*]AccessPot - File access detected. UID = %ld, Proc Name = %s, Proc ID = %d\n", senderUid, processName, pid);

             //copy all the data to our buffer
             sprintf(buffer, "%i|%s|%d", senderUid.val, processName, pid);
             //send the buffer to our userland application
             send_msg_to_user(buffer);
             //free the buffer memory
             kfree(buffer);
        }

        //free the memory for the filename
        kfree(kernFl);

        //call the original sys_open function
        real_do_sys_open(dfd, filename, flags, mode);
}

static int resolve_hook_address(struct ftrace_hook *hook)
{
        //get the address of the function requested
        hook->address = kallsyms_lookup_name(hook->name);
 
        //if the the function failed (result = 0),
        if (!hook->address) 
        {
                //inform the user
                pr_debug("Unresolved Function Name: %s\n", hook->name);
                //return a "No Entry Found" error code
                return -ENOENT;
        }
 

        //set the address of the original function to the address of the actual
        //function address found
        *((unsigned long*) hook->original) = hook->address;
 
        //return that everything went OK
        return 0;
}

int fh_install_hook(struct ftrace_hook *hook)
{
        //a variable to store the resulting value
        //of the calling functions
        int errorVal;
 
        //get the address of the function specified and save it
        //inside the ftrace_hook structure
        errorVal = resolve_hook_address(hook);

        //the error value was 1 (unresolved function name)
        if (errorVal)
        {
                //inform the user
                pr_debug("resolve_hook_address() failed!");
                //return the function with the error value received (1)
                return errorVal;
        }
 
        //specify the handler function for our hook
        hook->ops.func = fh_ftrace_handler;
        //initialize the hook flags
        hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;
 
        //enable our ftrace filter ONLY for our function only (hence why we pass the function address)
        errorVal = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);

        //if ftrace_set_filter_ip failed,
        if (errorVal) 
        {
                //notify the user
                pr_debug("ftrace_set_filter_ip() failed: %d\n", errorVal);
                //return the error value received
                return errorVal;
        }
 
        //enable the tracing of our function
        errorVal = register_ftrace_function(&hook->ops);

        //if the function tracing failed to start,
        if (errorVal) 
        {
                //notify the user
                pr_debug("register_ftrace_function() failed: %d\n", errorVal);
 
                //disable ftrace since an error occured by specifying the remove flag (third parameter)
                ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
 
                //return the error
                return errorVal;
        }
 
        //if we reached that far, everything went alright
        return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
        //declare a variable to hold the return
        //value of our functions
        int errorValue;
 
        //request a stop to the tracing being done by ftrace to our function
        errorValue = unregister_ftrace_function(&hook->ops);
        //If the function failed,
        if (errorValue)
                pr_debug("unregister_ftrace_function() failed: %d\n", errorValue); //inform the user
 
        //remove the filter that gives result for our function only (by providing true on the third argument)
        errorValue = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        if (errorValue) //if the function failed
                pr_debug("ftrace_set_filter_ip() failed: %d\n", errorValue); //inform the user
}


static void notrace fh_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                struct ftrace_ops *ops, struct pt_regs *regs)
{
        //using ftrace_ops, get the ftrace_hook instance (the parent structure)
        struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

        //check if the caller was our hook. If not,
        if(!within_module(parent_ip, THIS_MODULE))
        {
                //hijack eip and point it to our 'fake' function
                regs->ip = (unsigned long) hook->function;
        }
}

static int __init init_routine(void)
{
        //create a new netlink instance
        nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, NULL);

        //if no connection could be made,
        if (!nl_sk) 
        {
                //this is a fatal error, we infom the user
                pr_err("[-]AccessPot: Could not create netlink socket\n");
                //exit the initialization with a symbolic error message
                return 1;
        }

        //specify the name of the function to hook
        ftrace_do_sys_open.name = "do_sys_open";
        //specify our "fake" function that will act as the hijacker
        ftrace_do_sys_open.function = fh_do_sys_open;
        //specify an instance of the original function to be called
        ftrace_do_sys_open.original = &real_do_sys_open;

        //hook dod_sys_open, and check if the hooking was successful
        if(!fh_install_hook(&ftrace_do_sys_open))
        {
                //infom the user
                pr_debug("[*]AccessPot: do_sys_open hook installed successfully\n");
        }
        else
        {
                //this is a fatal error, we infom the user
                pr_err("[-]AccessPot: do_sys_open hook failed!");
                //exit the initialization with a symbolic error message
                return 1;
        }

        //inform the user that the module has loaded
        pr_debug("[*]AccessPot: module has been loaded\n");

        return 0;
}

static void __exit exit_routine(void)
{
        //release the netlink instance
        netlink_kernel_release(nl_sk);

        //remove our function hook
        fh_remove_hook(&ftrace_do_sys_open);

        //info the user that the module was unloaded
        pr_debug("[*]AccessPot: module has been unloaded\n");
}

//initialize the module load 
//and unload events
module_init(init_routine);
module_exit(exit_routine);