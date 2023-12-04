#!/usr/bin/python3 -u
#
#  Viruscheck the files added to the end of a listfile.
#
# Usage example: ./virus_check.py /opt/data/vcheck_shared/vcheck_filelist.all 3
#
# History:
#       25/09/2019      bocs         Creation
#       05/03/2020      bocs         Called by CrushFTP, check one file
#       20/03/2020      bocs         Support CrushFTP encryption
#       08/04/2020      bocs         Read the logfile continuously, check all files, run as daemon
#       12/04/2021      bocs         Get the full path from the log, check file moves, remove email sending, set max_filesize to large
#       11/08/2022      bocs		 Get the paths from a listfile, can run in parallel in n threads

import sys, json, os, subprocess, difflib
import xml.etree.ElementTree as ET
from datetime import datetime
from subprocess import Popen,PIPE
from os import path
import re

from time import sleep
import threading
from threading import Thread
import tempfile

import gnupg
import logging
gnupg_logger = logging.getLogger("gnupg")
#gnupg_logger.setLevel(logging.CRITICAL+1)
gnupg_logger.setLevel(logging.CRITICAL)


import vcheck_lib
from vcheck_lib import log_it,send_mail

my_dir='/opt/'
my_groups='/opt-data/groups/'
my_groups1='/opt/data/groups/'
vcheck_dir=my_dir + 'virus_check/'
vcheck_log=vcheck_dir +'virus_check.log'
quarantine_dir=vcheck_dir + 'quarantine/'
virusdb_dir=vcheck_dir + 'current'
temp_dir=vcheck_dir + 'temp/'

max_filesize=100*1024  # MB
mail_address='my@email.address'
nodename=os.uname().nodename
sleep_interval=0.2


def get_group( domain, user ):

    xmlf=my_dir + 'CrushFTP10/users/' + domain + '/groups.XML'
    xml_root = ET.parse( xmlf ).getroot()

    groupa=[]
    for item in xml_root.findall('./'):
        for subitem in item.findall('./'):
            if subitem.text==user:
                groupa.append( item.tag ) 

    # Choose the shortest groupname
    group=None
    gmin=1000
    for g in groupa:
        leng=len( g )
        if leng < gmin:
            group=g
            gmin=leng

    return( group )


def have_key( gpg, group ):


    if group == None:
        return False

    have_key=False
    for key in gpg.list_keys( secret=True, keys=group ):
        if key['uids'][0]==group:
            have_key=True
            break

    return( have_key )



def decrypt( gpg, encrypted_file, decrypted_file ):

    try:
        with open(encrypted_file, 'rb' ) as input_file:
            status=gpg.decrypt_file(input_file, passphrase='xxxxxx', output=decrypted_file)
        if not status.ok:
            with open(encrypted_file, 'rb' ) as input_file:
                status=gpg.decrypt_file(input_file, output=decrypted_file)
        if not status.ok:
            return( 'Decrypt error: ' + status.status + '\nStderr:\n' + status.stderr )
    except:
        return( "Error: " + str( sys.exc_info() ))

    return( None )


def virus_check(fname):

    try:
        fsize=os.stat( fname ).st_size
    except OSError as e:
        return( "Cannot stat file " + fname + ", not checked for viruses.\n" )
    else:
        if(fsize > max_filesize*1024*1024):
            return( fname + " size (" + str(fsize) + ") is greater than max_filesize (" + str(max_filesize) + " MB), not checked for viruses.\n" )

    checker=["uvscan", fname, "--MAXFILESIZE=" + str(max_filesize), "--MOVE=" + quarantine_dir, "--DAT=" + virusdb_dir ]

    p = subprocess.Popen( checker, bufsize=1, stdin=PIPE, stdout=PIPE, close_fds=True, universal_newlines=True)
    virchk_res = p.communicate()

    #print "virchk_res[0]=" + virchk_res[0]
    #print virchk_res[1]
    #print p.returncode

    ret_string=virchk_res[0]
    if virchk_res[1] != None:
        ret_string=ret_string + virchk_res[1]

    if 'File has been relocated' in ret_string or 'No file or directory found' in ret_string or p.returncode != 0:
        return( "Scanner return code is " + str( p.returncode ) + "\n" + ret_string )
    else:
        return( None )


def check_one_file( domain, username, file ):

    groupname=get_group( domain, username )

    # Monitoring check with group dim
    if groupname=='dim':
        #print( 'dim: ' + file )
        return( None )

    if path.basename( file )=='esden_communication.test':
        #print( 'esden_communication.test: ' + file )
        return( None )

    if file.find( '.filepart' ) >= 0:
        file=file.split('.filepart')[0]   # remove the ending .filepart
    elif file.find( '.part' ) >= 0:
        file=file.split('.part')[0]       # remove the ending .part
    elif file.find( '.temp' ) >= 0:
        file=file.split('.temp')[0]       # remove the ending .temp
    elif file.find( '.tmp' ) >= 0:
        file=file.split('.tmp')[0]       # remove the ending .tmp

    GPG = gnupg.GPG()

    # if group's files are encrypted (we have a key for the group) then decrypt
    if have_key( GPG, groupname ):

        (temp_fd, temp_file)=tempfile.mkstemp(dir=temp_dir ,prefix='tempfile.')
        os.close( temp_fd )

        dout=decrypt( GPG, file, temp_file )

        if dout != None:
            dout="File: " + groupname + " " + file + "\n" + dout
            log_it( vcheck_log, dout, False )
            return( dout )
        else:
            log_it( vcheck_log, groupname + " " + file + "decryption to " + temp_file + " is OK", False )

        out=virus_check( temp_file )

        if out != None:
            if 'File has been relocated' in out:
                send_mail(mail_address, nodename + ' ' + groupname + ': Virus found in file ' + file, out)
                # Relocate the original file
                qfulldir=quarantine_dir + path.dirname( file )
                if not path.exists( qfulldir ):
                    os.makedirs( qfulldir )
                os.rename( file, qfulldir + '/' + path.basename( file ))

                os.remove( quarantine_dir + temp_file )
            else:
                os.remove( temp_file )

            out="File: " + groupname + " " + file + "\n" + out
            log_it( vcheck_log, out, False )
            return( out )

        #os.remove( temp_file )

    else:
        # virus check without decryption
        out=virus_check( file )
        if out != None:
            if 'File has been relocated' in out:
                send_mail(mail_address, nodename + ' ' + groupname + ': Virus found in file ' + file, out)
            out="File: " + groupname + " " + file + "\n" + out
            log_it( vcheck_log, out, False )
            return( out )

    log_it( vcheck_log, groupname + " " + file + " OK", False )

    return( None )


def tailF( f ):
    "Listen for new lines added to file."
    while True:
        line = f.stdout.readline()
        yield line


# MAIN
if len(sys.argv) < 3:
    log_it( vcheck_log, "\nUsage:\n\t\t%s filelist max_parallel\n" % sys.argv[0], True )
    sys.exit( 1 )

filelist=sys.argv[1]
max_parallel=int(sys.argv[2])

os.chdir( vcheck_dir )

if not path.exists( quarantine_dir ):
    os.mkdir( quarantine_dir )

if not path.exists( temp_dir ):
    os.mkdir( temp_dir )

log_it( vcheck_log, sys.argv[0] + ' started.', False )

while True:
#if True:
    try:
        #For testing a new version:
        #fin=subprocess.Popen(['cat', filelist ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #for line in fin.stdout:
        fin=subprocess.Popen(['tail', '--lines=0', '-F', filelist ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in tailF(fin):
            line=line.decode()
            if re.search(':', line):
                (date, time, hostname, domain, user, file)=line.split(':')
                file=file.rstrip()
                while( threading.active_count()-1 >= max_parallel ):
                    sleep( sleep_interval )

                t = Thread(target=check_one_file, args=(domain, user, file))
                t.start()
            else:
                continue
    except:
        log_it( vcheck_log, filelist + " error: " + str( sys.exc_info() ), False)

    sleep( sleep_interval )
