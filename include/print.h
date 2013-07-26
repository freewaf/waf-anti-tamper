#ifndef _PRINT_H
#define _PRINT_H

#ifdef CLI_OTHER
#include <rg_lib/rg_syslog.h>
#include <app/cli/cli_transtion.h>
#endif

#ifdef CLI_OTHER
#define syslog_print_info(module, mnemonic, fmt, args...) \
    printk_info(module, mnemonic, fmt, ##args) 
    
#define msg_printf cli_printf
#else
#define syslog_print_info(module, mnemonic, fmt, args...) \
    printf(fmt, ##args);
    
#define msg_printf printf
#endif

#endif

