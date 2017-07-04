/*******************************************************************************
 * Copyright (C) 2017 Alessandro Bosco
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/

/* The five net hook:
 * NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, 
 * NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING
 * 
 * "FLAGS=%c%c%c%c%c%c",tcp_header->urg ? 'U' : '-', tcp_header->ack ? 'A' : '-', tcp_header->psh ? 'P' : '-', tcp_header->rst ? 'R' : '-', tcp_header->syn ? 'S' : '-', tcp_header->fin ? 'F' : '-'
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h> 
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/mutex.h>



#define DEVICE_NAME "cc_hooker"
#define CLASS_NAME  "cchlkm" 
#define MODULE_NAME "CC_Hooker"
#define LF          "\n"
#define BUFMSG_SIZE 256 /*IP SRC and PORT DST and general message*/

static DEFINE_MUTEX(k_lock); // mutex_unlock(&k_lock) //To unlock!

//Module info
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cave-canem LKM Network packets hook using device");
MODULE_AUTHOR("G04tb0y");

static struct nf_hook_ops nfho; // hook for incoming packet
static struct nf_hook_ops nfho_out; // hook for outgoing packet

static char buf[BUFMSG_SIZE]; // Message buffer
static char buf_out[BUFMSG_SIZE]; // Message buffer
static char rcv_buf[BUFMSG_SIZE]; // Recived message from user space
static char   message[BUFMSG_SIZE] = {0}; // final message 

static int    device_num; // device number
static struct class*  cc_char_class  = NULL; //driver class struct pointer
static struct device* cc_char_device = NULL; //driver device struct pointer // update to cdev
 
// The prototype functions for the character driver -- must come before the struct definition



/* prototypes */
static int     cc_dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

// Struct for file operations
static struct file_operations fops =
{
   .open = cc_dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};



/*
 * The hook function for filtering outgoing packets
 */
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
    
    char shost[17]; //src_host
    char dport[6];  //dst_port
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); //IP
    //struct udphdr *udp_header; //UDP
    struct tcphdr *tcp_header; //TCP

    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    // TCP
    if (ip_header->protocol == 6) {
        
        tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        src_port = htons((unsigned short int) tcp_header->source);
        dest_port = htons((unsigned short int) tcp_header->dest);
       
       if ((tcp_header->syn) && (tcp_header->ack)){// 2nd step of the 3-way hsk
            printk(KERN_INFO MODULE_NAME": [TCP_SYN_ACK-OUT] packet <--> src ip: %pI4, src port: %u; dest ip: %pI4, dest port: %u;\n", &ip_header->saddr, src_port, &ip_header->saddr, dest_port);
            
            //printk(KERN_DEBUG MODULE_NAME": preparing the alert message...\n");
            memset(&buf_out, 0, BUFMSG_SIZE);
            strncat(buf_out, "ALERT-TCP-OUT:", BUFMSG_SIZE - strlen(buf_out) - 1);
            
            sprintf(shost, "%pI4", &ip_header->saddr);
            strncat(buf_out, shost, BUFMSG_SIZE - strlen(buf_out) - 1);
            strncat(buf_out, ":", BUFMSG_SIZE - strlen(buf_out) - 1);
            
            sprintf(dport, "%d\n", dest_port);
            strncat(buf_out, dport, BUFMSG_SIZE - strlen(buf_out) - 1);
            
            if((BUFMSG_SIZE - strlen(message)) > strlen(buf_out)){
        
                strncat(message, buf_out, BUFMSG_SIZE - strlen(buf) - 1);
                //printk(KERN_DEBUG MODULE_NAME": massege to send to user space is: %s", message);
            }
            else{
                printk(KERN_ERR MODULE_NAME": Error Message Buffer is full, the alert will not be sent.\n");
            }
            
        }
       
    }

    // UDP 
    /* 
    if (ip_header->protocol==17) {
    
       udp_header = (struct udphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
       printk(KERN_INFO "[UDP-OUT] packet <-- src ip: %pI4, src port: %u; dest ip: %pI4, dest port: %u\n", &ip_header->saddr, src_port, &ip_header->saddr, dest_port);

    }*/
    return NF_ACCEPT;
}

/*
 * The hook function for filtering incoming packets
 */
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {

    char shost[17]; // src_host
    char dhost[17]; //dst_host
    char dport[6];  //dst_port

    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); //IP
    //struct udphdr *udp_header; //UDP
    struct tcphdr *tcp_header; //TCP
    
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    
    if (ip_header->protocol == 6) { //TCP
        
        tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        src_port = htons((unsigned short int) tcp_header->source);
        dest_port = htons((unsigned short int) tcp_header->dest);
        
        if ((tcp_header->syn) && !(tcp_header->ack)){// New incoming connection
            printk(KERN_INFO MODULE_NAME": [TCP_SYN-IN] packet <-- src ip: %pI4, src port: %u; dest ip: %pI4, dest port: %u;\n", &ip_header->saddr, src_port, &ip_header->saddr, dest_port);
            
            //printk(KERN_DEBUG MODULE_NAME": preparing the alert message...\n");
            memset(&buf, 0, BUFMSG_SIZE);
            strncat(buf, "ALERT-TCP-IN:", BUFMSG_SIZE - strlen(buf) - 1);
            
            sprintf(shost, "%pI4", &ip_header->saddr);
            strncat(buf, shost, BUFMSG_SIZE - strlen(buf) - 1);
            
            strncat(buf, ":", BUFMSG_SIZE - strlen(buf) - 1);
            
            sprintf(dport, "%d\n", dest_port);
            strncat(buf, dport, BUFMSG_SIZE - strlen(buf) - 1);
            
            if((BUFMSG_SIZE - strlen(message)) > strlen(buf)){
                strncat(message, buf, BUFMSG_SIZE - strlen(buf) - 1);
                //printk(KERN_DEBUG MODULE_NAME": massege to send to user space is: %s\n", message);
            }
            else{
                printk(KERN_ERR MODULE_NAME": Error Message Buffer is full, the alert will not be sent.\n");
            }
            
        }
    } else if(ip_header->protocol==IPPROTO_ICMP) { //ICMP
        snprintf(shost, 16, "%pI4", &ip_header->saddr);
        snprintf(dhost, 16, "%pI4", &ip_header->daddr);
        printk(KERN_INFO MODULE_NAME": [ICMP-IN] packet <-- from %s to %s\n",shost,dhost);
            
            //printk(KERN_DEBUG MODULE_NAME": preparing the alert message...\n");
            memset(&buf, 0, BUFMSG_SIZE);
            strncat(buf, "ALERT-ICMP-IN:", BUFMSG_SIZE - strlen(buf) - 1);
            strncat(buf, shost, BUFMSG_SIZE - strlen(buf) - 1);
            
            strncat(buf, ":", BUFMSG_SIZE - strlen(buf) - 1);
            
            strncat(buf, dhost, BUFMSG_SIZE - strlen(buf) - 1);
            strncat(buf, LF, BUFMSG_SIZE - strlen(buf) - 1);
            
            if((BUFMSG_SIZE - strlen(message)) > strlen(buf)){
                strncat(message, buf, BUFMSG_SIZE - strlen(buf) - 1);
                //printk(KERN_DEBUG MODULE_NAME": massege to send to user space is: %s\n", message);
            }
            else{
                printk(KERN_ERR MODULE_NAME": Error Message Buffer is full, the alert will not be sent.\n");
            }
    }
    
    //UDP
    /*else if (ip_header->protocol==17) {
        
        udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
        src_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
        printk(KERN_INFO "[UDP-IN] packet <-- src ip: %pI4, src port: %u; dest ip: %pI4, dest port: %u\n", &ip_header->saddr, src_port, &ip_header->saddr, dest_port);
        
    }*/
            //printk(KERN_INFO "[TCP-IN] packet <-- src ip: %pI4, src port: %u; dest ip: %pI4, dest port: %u; proto: %u FLAGS=%c%c%c%c%c%c\n", &ip_header->saddr, src_port, &ip_header->saddr, dest_port, ip_header->protocol, tcp_header->urg ? 'U' : '-', tcp_header->ack ? 'A' : '-', tcp_header->psh ? 'P' : '-', tcp_header->rst ? 'R' : '-', tcp_header->syn ? 'S' : '-', tcp_header->fin ? 'F' : '-');

    return NF_ACCEPT;
}

/*
 * Device operations
 */

static int cc_dev_open(struct inode *inodep, struct file *filep){
    if(mutex_trylock(&k_lock)){
        printk(KERN_INFO MODULE_NAME": Device has been opened \n");
        return 0;
    }
    else{
        printk(KERN_INFO MODULE_NAME": Device is busy");
        return -EBUSY;
    }
}


static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error = 0;
   // copy data to user space ( * to, *from, size)
   error = copy_to_user(buffer, message, strlen(message));
 
   if (error==0){
        //printk(KERN_INFO MODULE_NAME": [DEBUG]Sent message to the user(size: %zu)\n", strlen(message));
        memset(&message, 0, BUFMSG_SIZE); // reset the message buffer
        return 0;
   }
   else {
      printk(KERN_INFO MODULE_NAME": Failed to send %d characters to the user\n", error);
      return -EFAULT;              
   }
}


static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    memset(&rcv_buf, 0, BUFMSG_SIZE);
    if (len < BUFMSG_SIZE){ // Check if the message length from the user space is less then the MAX_SIZE
        sprintf(rcv_buf, "%s", buffer);
        printk(KERN_INFO MODULE_NAME": User say: %s\n", rcv_buf);
        return len;
    }
    
    return 0;
}


static int dev_release(struct inode *inodep, struct file *filep){
    mutex_unlock(&k_lock);
    printk(KERN_INFO MODULE_NAME": Device successfully closed\n");
    return 0;
}

/* 
 * Module init function
 */
int init_module() {

    printk(KERN_INFO MODULE_NAME": Initializing Cave-Canem_hooker LKM...\n");
    
    mutex_init(&k_lock); // init the mutex lock
    
    // device number(MAJOR)
    device_num = register_chrdev(0, DEVICE_NAME, &fops);
    if (device_num<0){
        printk(KERN_ERR MODULE_NAME": Failed to register the device number!\n");
        return device_num;
    }
    
    //printk(KERN_DEBUG MODULE_NAME": Device registered with number %d.\n", device_num);
 
    // Register the device class
    cc_char_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cc_char_class)){                
        unregister_chrdev(device_num, DEVICE_NAME); // unregister and clean
        printk(KERN_ERR MODULE_NAME": Failed to register device class!\n");
        return PTR_ERR(cc_char_class);
    }

    // Register the device driver
    cc_char_device = device_create(cc_char_class, NULL, MKDEV(device_num, 0), NULL, DEVICE_NAME);
    if (IS_ERR(cc_char_device)){               
        class_destroy(cc_char_class);           // ensure to deallocate the class driver
        unregister_chrdev(device_num, DEVICE_NAME); // unregister and clean
        printk(KERN_ERR MODULE_NAME": Failed to create the device!\n");
        return PTR_ERR(cc_char_device);
    }
    
    printk(KERN_INFO MODULE_NAME": Character Device created!(n: %d)\n", device_num);

    // Init incoming packet hook
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);         // Register the hook
    
    // Init outgoing packet hook
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);    // Register the hook
    
    printk(KERN_INFO MODULE_NAME": Initialization in-out register hook.\n");
    
    return 0;
}

/*
 * Module destroy
 */
 
void cleanup_module() {
    //Realese and unregister
    
    nf_unregister_hook(&nfho);
    //printk(KERN_DEBUG MODULE_NAME": Unregister nf_hook_in done.\n");
    nf_unregister_hook(&nfho_out);
    //printk(KERN_DEBUG MODULE_NAME": Unregister nf_hook_out done.\n");
    
    mutex_destroy(&k_lock);
    //printk(KERN_DEBUG MODULE_NAME": Mutex destroyed.\n");
    
    device_destroy(cc_char_class, MKDEV(device_num, 0));     // remove the device
    class_destroy(cc_char_class);                           // remove the device class and unregister
    unregister_chrdev(device_num, DEVICE_NAME);             // unregister the  device number
    //printk(KERN_DEBUG MODULE_NAME": Unregister device done.\n");
    
    printk(KERN_INFO MODULE_NAME": --Cave-canem_hooker LKM unloaded--.\n");

} 
