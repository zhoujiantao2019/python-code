#!/usr/bin/env python
# 
# $Header: oss/deploy/scripts/dcli.py /main/7 2009/01/07 21:11:52 rohansen Exp $
#
# dcli.py
#
# Copyright (c) 2008, Oracle and/or its affiliates.All rights reserved. 
#
#    NAME
#      dcli.py - distributed shell for Oracle storage
#
#    DESCRIPTION
#      distributed shell for Oracle storage
#
#    NOTES
#       requires Python version 2.3 or greater
# --------------------------
# Typical usage:
#
# create a text file of hosts named mycells
#
# execute a shell command on all cells:
#    dcli -g mycells "ls -l "
#
# or excute a cellcli command using -c option to specify cells:
#    dcli  -c sgbs21,sgbs22 cellcli -e list cell detail
#
# or do test printing of cell names:
#    dcli -g mycells -t
#
# or create a file to be copied and executed to a group of cells:
#    dcli  -g mycells -x cellwork.pl
#    dcli  -g mycells -x cellclicommands.scl
#
# File extension ".scl" is interpreted as a cellcli script file.
# When -x option value is a ".scl" file, then the file is copied
# and is used as input to cellcli on target cells.
#
# This program uses SSH for security between
# the host running dcli and the target cells.
#
#    MODIFIED   (MM/DD/YY)
#    rohansen    12/23/08 - support directory copy and destination option
#    rohansen    10/29/08 - added quotes to prevent shell expansion 
#    rohansen    09/16/08 - add vmstat option
#    rohansen    09/11/08 - kill child processes after ctrl-c
#    rohansen    06/27/08 - add -k option to push keys to cells
#    sidatta     07/22/08 - Changing name to dcli
#    rohansen    04/29/08 - more options
#    rohansen    04/01/08 - Creation
# 
# --------------------------

"""
Distributed Shell for Oracle Storage

This script executes commands on multiple cells in parallel threads.
The cells are referenced by their domain name or ip address.
Local files can be copied to cells and executed on cells.
This tool does not support interactive sessions with host applications.
Use of this tool assumes ssh is running on local host and cells.
The -k option should be used initially to perform key exchange with
cells.  User may be prompted to acknowledge cell authenticity, and
may be prompted for the remote user password.  This -k step is serialized
to prevent overlayed prompts.  After -k option is used once, then
subsequent commands to the same cells do not require -k and will not require
passwords for that user from the host.
Command output (stdout and stderr) is collected and displayed after the
copy and command execution has finished on all cells.
Options allow this command output to be abbreviated.

Return values:
 0 -- file or command was copied and executed successfully on all cells
 1 -- one or more cells could not be reached or remote execution
      returned non-zero status.
 2 -- An error prevented any command execution

Examples:
 dcli -g mycells -k
 dcli -c stsd2s2,stsd2s3 vmstat
 dcli -g mycells cellcli -e alter iormplan active
 dcli -g mycells -x reConfig.scl
"""
import os
import os.path
import time
import stat
import re
import sys
import socket
import popen2
import platform
import threading
import signal
from optparse import OptionParser

# dcli version displayed with --version
version = "0.3"
# default assignment for SSH port
PORT = 22
# timeout used to check aliveness of hosts
TIMEOUT = 1.0
# default location of SSH program
SSH = "/usr/bin/ssh"
# default location of SCP program
SCP = "/usr/bin/scp"
# test mode for test configurations
TESTMODE=''
# SSH file definitions:
SSHSUBDIR=".ssh"
SSHDSAFILE="id_dsa.pub"
SSHRSAFILE="id_rsa.pub"
SSHKEY=None

# Error class used to handle environment errors (e.g. file not found)
class Error(Exception):
    def __init__(self, msg):
        self.msg = msg

# UsageError class is used to handle errors caused by invalid options
class UsageError(Exception):
    def __init__(self, msg):
        self.msg = msg

def buildCellList(cells, filename, verbose):
    """
    Build a list of unique cells which will be contacted by dcli.

    Takes a list of cells and a filename.
    The file is read, and each non-empty line that does not start with #
    is assumed to be a cell.
    Unique cells are added to a list.
    Returns the list of unique cells.
    """
    celllist = []
    if filename :
        filename = filename.strip()
        try :
            fd = open(filename);
            lines = fd.readlines()
            for line in lines :
                line = line.strip();
                if len(line) > 0 and not line.startswith("#") :
                    celllist.append(line)
        except IOError, (errno, strerror):
            raise Error("I/O error(%s) on %s: %s" %
                        (errno, filename, strerror))
        
    if cells :
        for cline in cells:
            cellSplit = cline.split(",");
            for cell in cellSplit :
                celllist.append(cell.strip());

    uniqueCellList = []
    for c in celllist :
        if c not in uniqueCellList:
            uniqueCellList.append(c);
    return uniqueCellList;

      
def buildCommand( args, verbose ):
    """
    Build a command string to be sent to all hosts.

    Command arguments can be used to build the command to
    be sent to hosts.
    """
    command = ""
    if args:
        for word in args:
            command += " " + word;
    return command

def checkFile( filepath, isExec, verbose):
    """
    Test for existence and permissions of file to be copied or executed remotely.

    The file is tested for read and execute permissions.
    """
    filepath = filepath.strip()
    if not os.path.exists(filepath):  
        raise Error("File does not exist: %s" % filepath );
    if isExec:
        if not os.path.isfile(filepath): 
            raise Error("Exec file is not a regular file: %s" % filepath );
    elif not os.path.isfile(filepath) and not os.path.isdir(filepath): 
        raise Error("File is not a regular file or directory: %s" % filepath );
    st = os.stat(filepath)
    mode = st[stat.ST_MODE]
    if isExec and os.name == "posix" and not (mode & stat.S_IEXEC):   # same as stat.S_IXUSR
        raise Error("Exec file does not have owner execute permissions");

def checkKeys( verbose):
    """
    Test for existence of rsa or dsa public keys for current user.

    Search for dsa, and then rsa public key files in the current users
    .ssh directory.  The first file found is read and will be sent to
    the remote cells to be added to authorized_key file.
    The default public key file names for ssh protocol version 2 are
    sought. These are id_dsa.pub and id_rsa.pub in ~/.ssh.
    """
    global SSHKEY
    sshDir = os.path.join( os.path.expanduser("~"), SSHSUBDIR )
    rsaKeyFile = os.path.join( sshDir, SSHRSAFILE );
    dsaKeyFile = os.path.join( sshDir, SSHDSAFILE );
    if os.path.isfile(dsaKeyFile):
        f = open(dsaKeyFile )
        SSHKEY = f.read().strip()
        if (verbose ): print "DSA KEY: " + SSHKEY
        f.close()
    elif os.path.isfile(rsaKeyFile):
        f = open(rsaKeyFile )
        SSHKEY = f.read().strip()
        if (verbose ): print "RSA KEY: " + SSHKEY
        f.close()
    else:
        raise Error("Neither RSA nor DSA keys have been generated for current user.\n"
                    "Run 'ssh-keygen -t dsa' to generate an ssh key pair.");

def checkVmstat( vmstatOptions, verbose ):
    """
    Check vmstat option for valid periodic statistic options.

    Returns a repeat count and a command to be sent to cells.
    Returns null for repeat count if the option appears to be not periodic,
    e.g. -f, -s, -m, -p, -d, -V
    Periodic options, delay, and count are transformed into repeat count
    and modified command.
    Periodic options are "-n, -a, -S"
    Repeat count returned is either 1 or the last number in the option.
    Count of -1 indicates no repeat was given, so repeat indefinitely.
    Modified command is also returned, which is the command sent to cells.
    The repeat count will be appended in command loop
    --vmstat=       count       command
    ""              1           "vmstat"
    "3"              -1         "vmstat 3 "
    "3 10"           10         "vmstat 3 "
    "2 1"           1           "vmstat 2 "
    "-a 3"          -1          "vmstat -a 3 "
    """
    repeat = None
    delay = None
    vmstatCommand = "vmstat "
    vmOpts = vmstatOptions.split()
    for op in vmOpts:
        if op in ("-f","-s","-m","-p","-D", "-d","-V"):
            return None, None

        num = getInt(op)
        # less that 1 for delay or count is invalid
        if num != None and num < 1 :
            return None, None
        if num:
            if repeat :
                # more than 2 numbers as options
                return None, None
            elif delay:
                repeat = num 
            else:
                delay = num
        elif op != "-n":
            # we handle -n ourselves
            vmstatCommand += op + " "
    #default delay is immediate (no repeat)
    if  delay:
        vmstatCommand += "%d " % delay

        # default repeat is infinite
        if not repeat:
            repeat = -1
    
    else:
        #without delay, default repeat is 1
        vmstatCommand += "1 "
        repeat = 1

    return repeat, vmstatCommand


def copyAndExecute( cells, copyfile, execfile, destfile, command, user,
                    options, scpOptions, verbose ) :
    """
    Send file or a command to execute on a list a cells.

    A thread is started for each cell.
    Input cells is a map (hostname:ipaddress) of the good cells.
    Input command is string to be executed via ssh on each cell.
    Input copyfile is a file to be copied to each cell over scp.
    Input execfile is a file to be copied and executed on each cell.
    Input user is login name to be used on remote cells
    Input options is ssh or scp options to be passed through to ssh or scp
    Input scpOptions are scp options to be passed through to scp
    The response is collected as a list of lines.
    Finally wait for all cells to complete and
    Return status map (return codes per cell) and
    output map (lines from stdout and stderr per cell).
    """
    updateLock = threading.Lock()
            
    class WorkThread (threading.Thread):
        """
        Command thread issues one command to one cell.
        
        one thread is created for each cell
        allowing parallel operations.
        """
        def __init__( self, cell ):
             threading.Thread.__init__(self)
             self.cell = cell
             self.child = None
        def run(self):
            """
            One thread for each WorkThread.start()
            """
            if verbose : print "...entering thread for %s:" % self.cell
            childStatus = 0
            childOutput = [];
            opString = " ";
            scpOpString = " ";
            if options:
                opString += options + " "
            if scpOptions:
                scpOpString += scpOptions + " "
            else:
                scpOpString = opString
            if execfile and scpOpString.find("-p") < 0 :
                scpOpString += "-p "
                           
            sshUser = ""
            scpHost = self.cell
            if user:
                sshUser = "-l " + user + " "
                scpHost = user + "@" + scpHost

            if SSHKEY :
                # Perform the -k option step by sending the public key to cell
                # This will be serialized because host identity and password prompts
                # could overlay each other if the occur together.
                sshCommand = "ssh " + opString + sshUser + self.cell +  \
                    " \" mkdir -pm 700 ~/.ssh; if grep -qs '" + SSHKEY + \
                    "' ~/.ssh/authorized_keys  ; then echo ssh key already exists ; elif echo '" + \
                    SSHKEY + "' >> ~/.ssh/authorized_keys ; then chmod 644 ~/.ssh/authorized_keys ;" + \
                    " echo ssh key added ; fi \""
                if TESTMODE:
                    sshCommand = "echo " + sshCommandS
                updateLock.acquire()                
                childStatus, l = self.runCommand( sshCommand )
                updateLock.release()
                childOutput.extend(l)
                    
            if not childStatus and file :
                if  TESTMODE:
                    # for testing
                    scpCommand = "echo scp " + file +  " " + scpHost + ":" + destname
                else:
                    scpCommand = SCP + scpOpString + file +  " " + scpHost + ":" + destname

                childStatus, l = self.runCommand( scpCommand )
                childOutput.extend(l)
                
            if not childStatus and command :
                if  TESTMODE:
                    # for testing
                    sshCommand = "echo ssh " + opString + sshUser  + self.cell + " " + command
                else:
                    sshCommand = SSH + opString + sshUser + self.cell + " " + command
                childStatus, l = self.runCommand( sshCommand )
                childOutput.extend(l)
            updateLock.acquire()
            status[self.cell] = childStatus
            output[self.cell] = childOutput
            updateLock.release()
            if verbose : print "...exiting thread for %s status: %d" % (self.cell, childStatus)
            return

        def runCommand( self, sshCommand):
            """
            Run a command in a subprocess and return its status and output lines.

            ssh (or scp) command is run is a subprocess.  Stdout and stderr are
            collected.  This routine waits for completion of the subprocess and
            returns the completion code and any output lines.
            """
            if verbose : print "execute: %s " % sshCommand
            status = 0
            if os.name == "posix":
                child = popen2.Popen4( sshCommand )
                self.child = child
                r = child.fromchild
                w = child.tochild     
                w.close()
                l = r.readlines()
                r.close()
                try:
                    status = child.wait()
                except OSError,e:
                    # os error 10 (no child process) is ok
                    if e.errno ==10:
                        if verbose : print "No child process %d for wait" % child.pid
                    else:
                        raise
            else:
                r,w = popen2.popen4( sshCommand )
                # we assume non-interactive commands
                # close stdin so noone waits for us
                w.close()
                l = r.readlines()
                r.close()
            return status, l
        
    #end of method and WorkThread class    

    # Prepare and spawn threads to SSH to cells
    output = {}
    status = {}
    waitList = []
        
    if  (command or execfile) and not TESTMODE and not os.path.exists(SSH):
        raise Error ( "SSH program does not exist: %s " % SSH )
    elif (copyfile or execfile) and not TESTMODE and not os.path.exists(SCP):
        raise Error ( "SCP program does not exist: %s " % SCP )
        
    file = copyfile or execfile
    if file:
        file = file.strip()
        basename = os.path.basename(file)
        destname = basename
        
        if destfile:
            destname = destfile
            
        if execfile:
            # an exec file can be copied to a directory or copied to a file
            # with a different name.
            
            if execfile.strip().endswith(".scl"):
                command = "if [[ -d " + destname + " ]]; then cellcli -e @" +\
                          destname + "/" + basename + " ; else cellcli -e @" +\
                          destname + " ; fi"
            else:
                absdestname = destname
                if not os.path.isabs(destname):
                    absdestname = "./" + destname
                command = "if [[ -d " + destname + " ]]; then " + \
                          absdestname + "/" + basename + " ; else " +\
                          absdestname + " ; fi"

    # enclose command in single quotes so shell does not interpret arguments
    # pre-existing single quotes must be escaped to survive
    # if quotes aready exist then don't change it
    if command and not (re.match("^'.*'$", command)
                        or re.match("^\".*\"$", command)):
        command = command.replace("'","'\\''")
        command = "'" + command + "'"

    try:
        for cell in cells.keys():
            cellThread = WorkThread( cell )
            waitList.append(cellThread)
            cellThread.start()

        for thread in waitList:
            #we must use time'd join to allow keyboard interrupt
            while thread.isAlive():
                thread.join(1)

    except KeyboardInterrupt:
        print "Keyboard interrupt"
        for thread in waitList:
            if thread.isAlive() and thread.child:
                try:
                    print "killing child pid %d..." % thread.child.pid
                    os.kill(thread.child.pid, signal.SIGTERM)
                    t = 2.0  # max wait time in secs
                    while thread.child.poll() < 0:
                        if t > 0.5:
                            t -= 0.25
                            time.sleep(0.25)
                        else:  # still there, force kill
                            os.kill(thread.child.pid, signal.SIGKILL)
                            time.sleep(0.5)
                            thread.child.poll() # final try
                            break
                except OSError,e:
                    if e.errno != 3:
                        # errno 3 .."no such process" ... is ok
                        raise
#           we should call join to cleanup threads but it never returns                    
#           thread.join(5)  --- this never returns after ctrl-c
        raise KeyboardInterrupt
    
    return status, output

def getInt( str ):
    """
    Convert string to number.  Return None if string is not a number
    """
    try:
        num = int(str)
    except ValueError:
        return None
    return num

def listResults( cells, statusMap, outputMap, listNegatives, regexp):
    """
    list result output from cells.

    listNegatives option restricts output by listing only lines from
    cells which returned non-zero status from copy or command execution.
    regexp option restricts output by filtering-out lines which match a
    regular expression.
    We print output in "cells" order which is order given in user group
    file and command line cell list.
    """
    if listNegatives :
        okCells = []
        for cell in cells:
            if cell in statusMap.keys() and statusMap[cell] == 0:
                okCells.append(cell)
        if len(okCells) > 0:
            print "OK: %s" % okCells

    compiledRE = None
    if regexp:
        reCells = []
        compiledRE = re.compile(regexp)
        for cell in cells:
            if cell in outputMap.keys():
                output = outputMap[cell]
                for l in output:
                    if compiledRE.match(l.strip()):
                        reCells.append(cell)
                        break
        if len(reCells) > 0:
            print "%s: %s" % (regexp, reCells)
        
    for cell in cells:
        if cell in outputMap.keys():
            if not listNegatives or statusMap[cell] > 0:
                output = outputMap[cell]
                for l in output:
                    if not compiledRE or not compiledRE.match(l.strip()):
                        print "%s: %s" % (cell, l.strip())

def listVmstatHeader(headers, maxLenCellName, header1Widths, header2Widths):
    """
    print two vmstat headers aligned according to field widths
    """
    print "%s %s" % (" ".rjust(maxLenCellName),
                     listVmstatLine(header1Widths, headers[0].split()))
    print "%s:%s" %  (time.strftime('%X').rjust(maxLenCellName),
                       listVmstatLine(header2Widths, headers[1].split()))

def listVmstatLine( widths, values ):
    """
    return one line of vmstat values right justified in fields of max widths 
    """
    result = ""
    i = -1     
    for v in values:
        i += 1
        result += "%s " % str(v).rjust(widths[i])
    return result 

def listVmstatResults( cells, statusMap, outputMap, vmstatOps, count):
    """
    display results for the vmstat option.
    
    header lines are displayed unless suppressed by -n option.
    fields are aligned using the widest value in the output.
    Minimum, Maximum, and Average rows are added if there is more than
    one row of values.
    """
    MINIMUM = "Minimum"
    MAXIMUM = "Maximum"
    AVERAGE = "Average"
    
    minvalues = []
    maxvalues = []
    #approximate field widths for vmstat... these are minimums
    #           procs   memory  swap  io   system  cpu
    header1Widths = [5,   27,     9,   11,  11,     14 ]
    fieldWidths = [2,2, 6,6,6,6,   4,4,  5,5, 5,5,    2,2,2,2,2]
    total = []

    # use local time as max name width (it's used in header2)
    maxLenCellName = len(time.strftime('%X'))
    outputCount = len(outputMap.keys())
    for cell in outputMap.keys():
        if maxLenCellName < len(cell):
            maxLenCellName = len(cell)
        output = outputMap[cell]
        values = output[-1].split()
        i = -1
        for v in values:
            i += 2
            vInt = getInt(v)
            if vInt == None:
                continue
            if len(minvalues) <= i: 
                minvalues.insert(i, vInt)
            elif minvalues[i] > vInt:
                minvalues[i] = vInt
                                 
            if len(maxvalues) <= i:
                maxvalues.insert(i, vInt)
            elif maxvalues[i] < vInt:
                maxvalues[i] = vInt
            if len(total) <= i :
                    total.insert(i, 0)
            total[i] += vInt
            if len(fieldWidths) == i :
                fieldWidths.insert(i, len(v))
            elif fieldWidths[i] < len(v):
                fieldWidths[i] = len(v)
                
    maxLenCellName = max([maxLenCellName, len(MAXIMUM), len(MINIMUM), len(AVERAGE)])            
    # if not -n then print the header each time
    # with -n we only print on first invocation
    if count == 0 or vmstatOps.find("-n") == -1 :
        listVmstatHeader(outputMap.values()[0], maxLenCellName, header1Widths, fieldWidths )
             
    # list the output in key order, followed by min, max, and average                   
    for cell in cells:
        if cell in outputMap.keys():
            output = outputMap[cell]
            values = output[-1].split()
            print "%s:%s" % (cell.rjust(maxLenCellName), listVmstatLine(fieldWidths, values))
            headerNeeded = False
                     
    if outputCount > 1:
        print "%s:%s" % (MINIMUM.rjust(maxLenCellName), listVmstatLine(fieldWidths, minvalues))
        print "%s:%s" % (MAXIMUM.rjust(maxLenCellName), listVmstatLine(fieldWidths, maxvalues))
        avgvalues = []
        for v in total:
            avgvalues.append( int(round(v/outputCount)) )
        print "%s:%s" % (AVERAGE.rjust(maxLenCellName), listVmstatLine(fieldWidths, avgvalues))

                        

def main(argv=None):

    """
    Main program.

    This builds the option handler and handles help and usage errors.
    Then calls buildCommand to build the command to be sent.
    Then calls buildCellList to build a list of cells to connect with.
    Then calls test cells to determine which ones can connect.
    Then calls copyAndExecute to send or execute commands to all good cells.
    Then calls listResults to optionally abbreviate and list output
    Finally it returns 0, 1, or 2 based on results.
    """
    global TESTMODE        
    TESTMODE = ""
    if argv is None:
        argv = sys.argv
    elif argv[0].startswith("test"):
        # tests cannot rely on ssh ports
        TESTMODE = "test"
 
    usage = "usage: %prog [options] [command]" 
    parser = OptionParser(usage=usage, add_help_option=False,
                          version="version %s" % version)
    parser.add_option("-c", 
                      action="append", type="string", dest="cells",
                      help="comma-separated list of cells")
    parser.add_option("-d",
                     help="destination directory or file",
                     action="store", type="string", dest="destfile")
    parser.add_option("-f",
                     help="file to be copied",
                     action="store", type="string", dest="file")
    parser.add_option("-g", 
                     help="file containing list of cells",
                     action="store", type="string", dest="groupfile")

    # help displays the module doc text plus the option help
    def doHelp(option, opt, value, parser):
        print( __doc__ )
        parser.print_help()
        sys.exit(0)

    parser.add_option("-h", "--help",
                     help="show help message and exit",
                     action="callback", callback=doHelp)  
    parser.add_option("-k", 
                      action="store_true", dest="pushKey", default=False,
                      help="push ssh key to cell's authorized_keys file")        
    parser.add_option("-l", default="celladmin",
                     help="user to login as on remote cells (default: celladmin) ",
                     action="store", type="string", dest="userID")
    parser.add_option("-n", 
                      action="store_true", dest="listNegatives", default=False,
                      help="abbreviate non-error output ")
    parser.add_option("-r", 
                     help="abbreviate output lines matching a regular expression",
                     action="store", type="string", dest="regexp")
    parser.add_option("-s", 
                     help="string of options passed through to ssh",
                     action="store", type="string", dest="sshOptions")
    parser.add_option("--scp", 
                     help="string of options passed through to scp if different from sshoptions",
                     action="store", type="string", dest="scpOptions")
    parser.add_option("-t", 
                      action="store_true", dest="list", default=False,
                      help="list target cells ")
    parser.add_option("-v", action="count", dest="verbosity",
                      help="print extra messages to stdout")
    parser.add_option("--vmstat",
                      help="vmstat command options",
                      action="store", type="string", dest="vmstatOps")
    parser.add_option("-x",
                     help="file to be copied and executed",
                     action="store", type="string", dest="execfile")

    # stop parsing when we hit first arg to allow unquoted commands
    parser. disable_interspersed_args() 
    (options, args) = parser.parse_args(argv[1:])

    if options.verbosity :
        print 'options.cells: %s' % options.cells
        print 'options.destfile: %s' % options.destfile
        print 'options.file: %s' % options.file
        print 'options.group: %s' % options.groupfile
        print 'options.listNegatives: %s' % options.listNegatives
        print 'options.pushKey: %s' % options.pushKey
        print 'options.regexp: %s' % options.regexp
        print 'options.sshOptions: %s' % options.sshOptions
        print 'options.scpOptions: %s' % options.scpOptions
        print 'options.userID: %s' % options.userID
        print 'options.verbosity %s' % options.verbosity
        print 'options.vmstatOps %s' % options.vmstatOps
        print 'options.execfile: %s' % options.execfile
        print "argv: %s" % argv

    returnValue = 0
    try:
        command = None
        if len(args) > 0:
            command = buildCommand( args, options.verbosity )

        if not command and not (options.list or options.execfile 
                                or options.file or options.pushKey
                                or options.vmstatOps != None):
            raise UsageError("No command specified.")
        if command and options.execfile:
            raise UsageError("Cannot specify both command and exec file");
        if options.file and options.execfile:
            raise UsageError("Cannot specify both copy file and exec file");
        if options.listNegatives and options.regexp:
            raise UsageError("Cannot specify both non-error and regular expression abbrevation options");
        vmstatCount = None
        # an empty option value is is ok for vmstat
        if options.vmstatOps != None and options.vmstatOps == "":
            options.vmstatOps = " "
        if options.vmstatOps :
            if (options.execfile or options.file or command):
                raise UsageError("Cannot specify vmstat option with copy file, exec file, or command");
            if (options.listNegatives or options.regexp):
                raise UsageError("Cannot specify vmstat option with abbreviate options")
            vmstatCount, command = checkVmstat(options.vmstatOps, options.verbosity)
            if vmstatCount == None:
                command = "vmstat " + options.vmstatOps
        if options.pushKey:
            checkKeys(options.verbosity);
        clist = buildCellList( options.cells, options.groupfile, options.verbosity )

        if len(clist) == 0 :
            raise UsageError("No cells specified.")

        if options.execfile:
            checkFile(options.execfile, True, options.verbosity)
        if options.file:
            checkFile(options.file, False, options.verbosity)
        if options.destfile and not (options.execfile or options.file):
            raise UsageError("Cannot specify destination without copy file or exec file")
        if options.list:
            print "Target cells: %s" % clist

        # cells are divided into good and bad based on willingness to talk
        goodCells = {}
        badCells = []    
        if command or options.execfile or options.file or options.pushKey:
            # we may have something to do.  test connectivity first..
            goodCells, badCells = testCells(clist, options.verbosity)
            if options.verbosity and len(goodCells) > 0 :
                print "Success connecting to cells: %s" % goodCells.keys()
            if len(badCells) > 0 :
                returnValue = 1
                print >>sys.stderr,"Unable to connect to cells: %s" % badCells

        if len(goodCells) > 0 :
            if vmstatCount != None :
                # For vmstat, do periodic sampling of vmstat and print as we go.
                # the first time through the loop we retrieve just the boot stats
                # thereafter we retrieve a delayed sample (sampleCount =2)
                loopCount = 0
                sampleCount = 1
                while True:
                    statusMap, outputMap = copyAndExecute( goodCells, None, None, None,
                                             command + str(sampleCount), options.userID,
                                             options.sshOptions, options.scpOptions,
                                             options.verbosity);
                    if max( statusMap.values() ) > 0 :
                        #error returned  ... display results in usual fashion and exit
                        listResults( clist, statusMap, outputMap, None, None)
                        break
                    listVmstatResults( clist, statusMap, outputMap, options.vmstatOps,
                                        loopCount)
                    if vmstatCount >= 0 :                       
                        loopCount += 1
                        if loopCount >= vmstatCount :
                            break
                    sampleCount = 2
            else:             
                statusMap, outputMap = copyAndExecute( goodCells, options.file, options.execfile,
                                         options.destfile, command, options.userID,
                                         options.sshOptions, options.scpOptions,
                                         options.verbosity);
                listResults( clist, statusMap, outputMap, options.listNegatives,
                             options.regexp )
            values = statusMap.values() + [returnValue]
            returnValue = max( values )

    except UsageError, err:
        print >>sys.stderr, "Error: %s" % err.msg
        parser.print_help()
        # parser.error(err.msg) -- doesn't print usage options.
        return 2

    except Error, err:
        print >>sys.stderr, "Error: %s" % err.msg
        return 2

    except KeyboardInterrupt:
        # sys.exit(1)  does not work after ctrl-c
        os._exit(1)

    # return 1 for any other error
    return returnValue and 1


def testCells(cellList, verbose) :
    """
    Test cells for their ability to talk on their SSH port 22
    
    Builds a list of cells that can connect (good list)
    and a list of bad cells
    The good cell list is returned as a map:
    cellname : ipaddress
    """
        
    good = {}
    bad = []

    for cell in cellList :
        
        ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        ts.settimeout(TIMEOUT);
        try:
            ipaddress = socket.gethostbyname(cell)
            if not TESTMODE:
                ts.connect((ipaddress, PORT))
            good[cell] = ipaddress
        except socket.error, e:
            if verbose: print "socket error: %s" % e
            bad.append(cell)
        except socket.timeout, e:
            if verbose: print "socket timeout: %s" % e
            bad.append(cell)
    return good, bad
    
# Main program

if __name__ == "__main__" :
    sys.exit(main())
