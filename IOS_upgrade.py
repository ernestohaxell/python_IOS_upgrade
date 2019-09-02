from netmiko import ConnectHandler
from getpass import getpass
from time import time
import threading

#####################VARIABLES##################################################
##################### host variables ###########################################
hosts_file = "hosts.txt"
username = input("Enter your User ID: ")
password = getpass()
transfer_server = "1.1.1.1"

################### Platform Variables #########################################
plat_c3650c = {
    'image':'c3560c405-universalk9-mz.152-2.E8.bin',
    'hash' : 'e2dd3fe475296a44fc64addc46c18bd1',
    'size' : 20004864
}

plat_c3750x =  {
    'image': 'c3750e-universalk9-mz.150-2.SE11.bin',
    'hash' : '440af3778a547f6394c893c4dd654b8f',
    'size' : 20442368
}

plat_c3850 = {
    'image' :'cat3k_caa-universalk9.SPA.03.06.08.E.152-2.E8.bin',
    'hash' : 'a04a54d69cb2b4d2867ed369e73598ae',
    'size' : 305292424 ,
    'sw_check' : '03.06.08E'
}

plat_c4500 = {
    'image' : 'cat4500es8-universalk9.SPA.03.10.01.E.152-6.E1.bin',
    'hash' : '08df1010cca60587cadeef6e3bd2ca3f',
    'size' : 393368640
}

plat_c6840x = {
    'image': 'c6848x-adventerprisek9-mz.SPA.152-2.SY3.bin',
    'hash' : '35c9f08e23e5b5674b8793e41f2a53c5',
    'size' : 94529496
}

plat_isr4300 = {
    'image': 'isr4300-universalk9.16.03.06.SPA.bin',
    'hash' : '7d1efe10780fcac2f1d385c94248e76b',
    'size' : 459643227
}

plat_isr4400 = {
    'image': 'isr4400-universalk9.16.03.06.SPA.bin',
    'hash' : '5cbf9e5c5ce5c77a281833667d0ea627',
    'size' : 459792128
}

plat_isr1100 = {
    'image': 'c1100-universalk9_ias.16.06.04.SPA.bin',
    'hash' : '27b52fd2b53f1548a973a563d5725b4e',
    'size' : 355970456
}
############ Images ############################################################
#c4500_image = "cat4500es8-universalk9.SPA.03.08.05.E.152-4.E5.bin" - for older SUPs than 9
######### Hashes ###############################################################
#c4500_hash = "d0c83da6b24fac6415f8a7b582075b2b" - for older SUPs than 9
######### Image Sizes ##########################################################
#c4500_size = 512272280 - for older SUPs than 9
######## END OF VARIABLES ######################################################

######## Main Function #####################################################################
def ssh_session(ios_device):

    list_versions = ["WS-C3560C" , "WS-C3750X" , "WS-C3850" , "cat4500es8" , "c6848x"  , "ISR43" , "ISR44" , "C1111" ]

    net_connect = ConnectHandler( device_type=ios_device['device_type'], ip=ios_device['ip'],
                                username=ios_device['username'], password=ios_device['password'] )
    print("Connecting to: " + ios_device['ip'])

######## Function to find specific strings within string #######################
    def between(value, a, b):
        pos_a = value.find(a)
        if pos_a == -1:
            return ""

        pos_b = value.rfind(b)

        if pos_b == -1:
            return ""

        adjusted_pos_a = pos_a + len(a)

        if adjusted_pos_a >= pos_b:
            return ""

        return value[adjusted_pos_a:pos_b]

######## Image Check Function #####################################

    def image_check(image_ver):
        print("Checking for " + image_ver)
        output_version = net_connect.send_command("show version")
        image_version = 0
        image_version = output_version.find(image_ver)
        return image_version

######## Generic Storage check Function ########################################

    def storage_check(image_ver , storage):
        print("Checking if image is stored in " + storage)
        output_storage = net_connect.send_command("show " + storage + ":")
        storage_version = 0
        storage_version = output_storage.find(image_ver)
        return storage_version

####### Generic Veirfy MD5 Hash Function #######################################

    def hash_verify(location, image, dev_hash):
        print("Verifying the Hash for image integrity...")
        output_hash = net_connect.send_command("verify /md5 " + location + ":" + image, expect_string=r'#', delay_factor=35)
        print(output_hash)
        hash = 0
        hash = output_hash.find(dev_hash)
        return hash

###### Generic Verify Space on Storage #########################################

    def free_space(storage, img_size):
        print("Verifying there is enough space for new image...")
        output_space = net_connect.send_command("show " + storage + ": | i bytes free")
        type_of_space = 0
        type_of_space = output_space.find("bytes free")
        if type_of_space > 0:
            bytes_free = between(output_space,"(", "bytes")
            available_space = int(bytes_free) - img_size
            print("Available Space: " + str(available_space))
            return available_space
        else:
            output_space = net_connect.send_command("show " + storage + ": | i bytes available")
            output_space_split = output_space.split()
            available_space = int(output_space_split[0])
            print("Available Space: " + str(available_space))
            return available_space



####### Generic Copy Image To Single Storage Function ##########################

    def save_img_single_storage(image_ver, storage, loc, dev_hash, img_size):

        if free_space(storage, img_size) > 0:
            print("There is enough space to copy the new image")

            if storage_check(image_ver , storage) < 0:
                print("Copying " + image_ver + " from " + transfer_server + " to " + storage )
                output = net_connect.send_command_timing("copy http://" + transfer_server + "/network_os/Cisco/" + image_ver + " " + storage + ":" + image_ver )
                print(output)
                net_connect.send_command("\n", expect_string=r'#', delay_factor=35)
                print(output)

            else:
                print("Image already stored in " + storage)

            if hash_verify(storage, image_ver, dev_hash) > 0:
                print("Image is valid! ")
                print("Deleting boot var...")
                output = net_connect.send_config_set("no boot system")
                print("Setting boot var to: " +  image_ver )
                output = net_connect.send_config_set("boot system " + loc + " " + storage + ":" + image_ver)
                print(output)
                print("Saving configuration...")
                output = net_connect.send_command("write mem")

            else:
                print("Hash does not match! Image might be corrupted...")
                print("Upgrade Aborted...")

        else:
            print("There is not enough space to copy the new image, free some space and try again...")

####### Generic Copy Image to dual Storage Function ############################

    def save_img_dual_storage(image_ver, storage, sec_storage, loc, dev_hash, img_size):

        if free_space(storage, img_size) > 0:
            print("There is enough space to copy the new image")

            if storage_check(image_ver , storage) < 0:
                print("Copying " + image_ver + " from " + transfer_server + " to " + storage )
                output = net_connect.send_command_timing("copy http://" + transfer_server + "/network_os/Cisco/" + image_ver + " " + storage + ":" + image_ver )
                print(output)
                net_connect.send_command("\n", expect_string=r'#', delay_factor=35)
                print("Finished copying to " + storage + ": " + output)

            else:
                print("Image already stored in " + storage)
        else:
            print("There is not enough space to copy the new image on the primary storage, free some space and try again...")

        if free_space(sec_storage, img_size) > 0:
            print("There is enough space to copy the new image")

            if storage_check(image_ver , sec_storage) < 0:
                print("Copying " + image_ver + " from " + transfer_server + " to " + sec_storage )
                output = net_connect.send_command_timing("copy http://" + transfer_server + "/network_os/Cisco/" + image_ver + " " + sec_storage + ":" + image_ver )
                print(output)
                net_connect.send_command("\n", expect_string=r'#', delay_factor=35)
                print("Finished copying to " + sec_storage +": " + output)

            else:
                print("Image already stored in " + sec_storage)

        else:
            print("There is not enough space to copy the new image on the secondary storage, free some space and try again...")

        if hash_verify(storage, image_ver, dev_hash) and hash_verify(sec_storage, image_ver, dev_hash) > 0:
            print("Images are valid! ")
            print("Deleting boot var...")
            output = net_connect.send_config_set("no boot system ")
            print("Setting boot var to: " +  image_ver )
            output = net_connect.send_config_set("boot system " + loc + " " + storage + ":" +  image_ver)
            print(output)
            print("Saving configuration...")
            output = net_connect.send_command("write mem")

        else:
            print("Hash does not match! Image might be corrupted...")
            print("Upgrade Aborted...")


######## Process to Find Platform #############################################
    for sw_ver in list_versions:
        print("Platform Check for " + sw_ver)
        output_version = net_connect.send_command("show version")
        int_version = 0
        int_version = output_version.find(sw_ver)

        if int_version > 0 :
            print("Platform Identified!: " + sw_ver)
            break

        else:
            print("Could not identify platform!")

######## Check Image ###########################################################
############ Process for C3560-C ###############################################
    if sw_ver == "WS-C3560C":

        image_version = image_check(plat_c3650c['image'])

        if image_version < 0:

            save_img_single_storage(plat_c3650c['image'], "flash", "", plat_c3650c['hash'], plat_c3650c['size'])

        else:
            print("Code is up to date!")
######## Process for 3750X######################################################
    elif sw_ver == "WS-C3750X":

        image_version = image_check(plat_c3750x['image'])

        if image_version < 0:
            switch_output = net_connect.send_command("show switch | include Ready")
            num_switches = 0
            num_switches = switch_output.count("Ready")
            print("There are " + str(num_switches) + " switches in the stack")
            range_num = num_switches + 1
            for i in range(1, range_num):
                stack_storage = "flash" + str(i)
                if free_space(stack_storage, plat_c3750x['size']) > 0:
                    print("There is enough space to copy the new image")
                    if storage_check(plat_c3750x['image'],stack_storage) < 0:
                        print("Copying " + plat_c3750x['image'] + " from " + transfer_server + " to " + stack_storage + ":" )
                        output = net_connect.send_command_timing("copy http://" + transfer_server + "/network_os/Cisco/" + plat_c3750x['image'] + " " + stack_storage + ":" + plat_c3750x['image'])
                        print(output)
                        net_connect.send_command("\n", expect_string=r'#', delay_factor=35)
                        print(output)

                    else:
                        print("Image already stored in flash")

                    if hash_verify(stack_storage, plat_c3750x['image'], plat_c3750x['hash']) > 0:
                        print("Image is valid! ")
                        if i == num_switches:
                            print("Deleting boot var...")
                            output = net_connect.send_config_set("no boot system")
                            print("Setting boot var to: " + plat_c3750x['image'] )
                            output = net_connect.send_config_set("boot system switch all flash:" + plat_c3750x['image'])
                            print(output)
                            print("Saving configuration...")
                            output = net_connect.send_command("write mem")
                        else:
                            print("Repeating image size check, image copy, and hash verification on the other stack members now...")
                    else:
                        print("Hash does not match! Image might be corrupted...")
                        print("Upgrade Aborted...")
                else:
                    print("There is not enough space in " + stack_storage + "...Free some space and try again...")

        else:
            print("Code is up to date!")

########## Process for C3850s ##################################################
    elif sw_ver == "WS-C3850":

        print("Checking for " + plat_c3850['image'])
        output_version = net_connect.send_command("show version")
        image_version = 0
        image_version = output_version.find(plat_c3850['sw_check'])

        if image_version < 0:
            if free_space("flash", plat_c3850['size']) > 0:
                print("There is enough space to copy the new image")
                if storage_check(plat_c3850['image'], "flash") < 0:
                    print("Copying " + plat_c3850['image'] + " from " + transfer_server + " to flash:" )
                    output = net_connect.send_command_timing("copy http://" + transfer_server + "/network_os/Cisco/" + plat_c3850['image'] + " flash:" + plat_c3850['image'] )
                    print(output)
                    net_connect.send_command("\n" , expect_string=r'#', delay_factor=15)
                    print(output)
                else:
                    print("Image already stored in flash")

            if hash_verify("flash", plat_c3850['image'], plat_c3850['hash']) > 0:
                print("The image has been verified!")
                switch_output = net_connect.send_command("show switch | include Ready")
                num_switches = switch_output.count("Ready")
                print("There are " + str(num_switches) + " switches in the stack")
                print("Checking software version to determine method of upgrade...")
                output_version = net_connect.send_command("show version | include INSTALL")
                image_version = 0
                image_version = output_version.find("16.6")
                if image_version > 0:
                    print("Version 16.x found...downgrading to 3.x")
                    output = net_connect.send_command("request platform software package install switch all file flash:" + plat_c3850['image'] + " new auto-copy", delay_factor=3)
                    print(output)
                else:
                    print("Version 3.x found...upgrading...")
                    if num_switches == 1:
                        output = net_connect.send_command("software install file flash:" + plat_c3850['image'] + " switch 1 new force" , expect_string=r'reload', delay_factor=3)
                        print(output)
                        net_connect.send_command_timing("no \n")
                        print(output)
                    elif num_switches > 1:
                        output = net_connect.send_command("software install file flash:" + plat_c3850['image'] + " switch 1-" + str(num_switches) + " new force" , expect_string=r'reload', delay_factor=4)
                        print(output)
                        net_connect.send_command_timing("no \n")
                        print(output)
            else:
                print("Hash does not match! Image might be corrupted...")
                print("Upgrade Aborted...")

        else:
            print("Code is up to date!")

######## Process for C4500 #####################################################
    elif sw_ver == "cat4500es8":

        image_version = image_check(plat_c4500['image'])
        autosync_commands = ["redundancy", "main-cpu", "auto-sync bootvar",
        "auto-sync config-register", "auto-sync standard" , "auto-sync startup-config" ]

        if image_version < 0:
            save_img_dual_storage(plat_c4500['image'], "bootflash", "slavebootflash", "flash", plat_c4500['hash'], plat_c4500['size'])
            print("Changing config-register...")
            output = net_connect.send_config_set("config-register 0x2102")
            print(output)
            print("Synching supervisor parameters...")
            output = net_connect.send_config_set(autosync_commands)
            print("Saving configuration...")
            output = net_connect.send_command("write mem")
            print(output)

        else:
            print("Code is up to date!")

######## Process for C6800 #####################################################
    elif sw_ver == "c6848x":

        image_version = image_check(plat_c6840x['image'])

        if image_version < 0:
            save_img_dual_storage(plat_c6840x['image'], "bootdisk", "slavebootdisk", "", plat_c6840x['hash'], plat_c6840x['size'])
            print("Changing config-register...")
            output = net_connect.send_config_set("config-register 0x2102")
            print(output)
            print("Saving configuration...")
            output = net_connect.send_command("write mem")
            print(output)

        else:
            print("Code is up to date!")

########## Process for ISR4300s #################################################
    elif sw_ver ==   "ISR43":

        image_version = image_check(plat_isr4300['image'])

        if image_version < 0:

            save_img_single_storage(plat_isr4300['image'], "bootflash", "flash", plat_isr4300['hash'], plat_isr4300['size'])

        else:
            print("Code is up to date")

########## Process for ISR4400s #################################################
    elif sw_ver ==   "ISR44":

        image_version = image_check(plat_isr4400['image'])

        if image_version < 0:

            save_img_single_storage(plat_isr4400['image'], "bootflash", "flash", plat_isr4400['hash'], plat_isr4400['size'])

        else:
            print("Code is up to date")

############# Process for ISR1100 ##############################################
    elif sw_ver == "C1111":

        image_version = image_check(plat_isr1100['image'])

        if image_version < 0:

            save_img_single_storage(plat_isr1100['image'], "bootflash", "flash", plat_isr1100['hash'], plat_isr1100['size'])
            print("Changing config-register...")
            output = net_connect.send_config_set("config-register 0x2102")
            print(output)
            print("Saving configuration...")
            output = net_connect.send_command("write mem")
            print(output)

        else:
            print("Code is up to date!")

############# End of Script ####################################################
    else:
        print("End of Script!")

    print("End of main program...")
    net_connect.disconnect()

######### Start of execution ###################################################

####### Read hosts IPs from file ###############################################
with open(hosts_file) as fp:
    hosts = fp.read().splitlines()

##### Creates dictionaries within a main dictionary for each host ##############
hosts_dictionary = {}

for devices in hosts:
    ip_address = devices
    ios_device = {
        'device_type' : 'cisco_ios',
        'ip' : ip_address,
        'username' : username,
        'password' : password
    }
    hosts_dictionary[ios_device['ip']] = ios_device

######### Start of Multithreading ##############################################

##### Separates the IP address of the host from its dictionary within a list ###
##### Created by the .items() ##################################################
starting_time = time()

config_threads_list = []

for ipaddr, device in hosts_dictionary.items():
    print ('Creating thread for: ', ipaddr)
    config_threads_list.append( threading.Thread( target=ssh_session, args=(device,) ) )

print ('\n---- Begin get config threading ----\n')
for config_thread in config_threads_list:
    config_thread.start()

for config_thread in config_threads_list:
    config_thread.join()

print ('\n---- End get config threading, elapsed time=', time() - starting_time)
