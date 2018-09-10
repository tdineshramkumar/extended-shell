"""
    Author: T Dinesh Ram Kumar
    Extending the shell functionality to provide additional piping functionality
    It allows output of one command to go to as many commands as needed by using new operators
    (||, |||, ||||, ...) and #
    Note: this works on top of shell
    Note: for a complete C based implementation of shell with this piping features and additional features
        Refer to: https://github.com/tdineshramkumar/networkprogramming-assignments/blob/master/NP-ASSIGNMENT1/shell.c
"""

import os
import sys
import re
from getopt import getopt, GetoptError


def usage():
    """
        This prints the usage string
    """
    print("Usage: {} [OPTION...] command".format(sys.argv[0]))
    print("Program to execute commands that need additional pipe facilities.")
    print("If you want to execute a command and pass its results to more than one command, ")
    print("create a pipe with ||.. with as many pipes as needed and follow it commands separated by #. ")
    print("Enclose the entire command within \" quotes so that executing shell does not treat"
          " # as beginning of comments ")
    print("Example: \n\t\t{0} \"cat file.txt || wc -l # grep ^f | sort\"".format(sys.argv[0]))
    print("Options:")
    print("\t--shell, -s SHELL\n\t\tUse SHELL for executing the individual commands\n\t\tDefault Shell: {0}"
          .format(SHELL))
    print("\t--print, -p\n\t\tPrint the parse tree")
    print("\t--help, -h\n\t\tGive the usage")


SHELL = "/bin/bash"     # shell to interpret the commands
print_parse_tree = False    # flag to indicate whether to print parse tree of not
try:
    SHORT_OPTIONS = "hs:p"  # Available options help, print, shell
    LONG_OPTIONS = ["help", "shell=", "print"]
    opts, argv = getopt(args=sys.argv[1:], shortopts=SHORT_OPTIONS, longopts=LONG_OPTIONS)
except GetoptError as error:    # if invalid options then print error, usage and then exit
    print(error)
    usage()
    sys.exit(-1)

for o, a in opts:
    if o in ("-h", "--help"):   # used to show usage
        usage()
        sys.exit(0)
    if o in ("--print", "-p"):  # used to print the parse tree (used for debugging)
        print_parse_tree = True
    if o in ("--shell", "-s"):  # used to change shell for executing the commands
        SHELL = a

if not argv:    # if no commands specified then print the usage and exit
    usage()
    sys.exit(-1)

input_command = " ".join(argv).strip()              # get the input command
input_command = re.sub("\s+", " ", input_command)           # remove unwanted spaces (trim spaces)
input_command = re.sub("\s*\|\s*", "|", input_command)      # compress all pipe symbols (remove spaces in-between pipes)
# """ Note that we need to start consider from ||... onwards single pipe | is taken care of by shell """
# input_commands = re.split("(\|{2,}|#)", input_command)
input_commands = re.split("(\|+|#)", input_command)          # break it into pieces to handle (tokenize the inputs)
input_commands = list(filter(lambda s: len(s.strip()), input_commands))   # remove empty tokens/strings

exit_error = lambda error_msg: [print(error_msg,file=sys.stderr), exit(-1)]     # default error handler
is_command = lambda command: True if re.match("[^\|\#]+", command) else False   # check if given string is command
is_pipes = lambda pipes: True if re.match("\|+", pipes) else False              # check if given string is pipe symbol
pipes_count = lambda pipes: len(re.match("\|+", pipes).group())                 # get the number of pipe operators used
is_separator = lambda separator: True if re.match("#", separator) else False    # check if separator
# Execute the command in the given shell
execute_command = lambda command: os.execlp(SHELL, SHELL, "-c", command)    # Note changes process context


"""
    parse and parse_pipes together parse the commands to build the parse tree
"""


def parse_pipes(commands):
    """
    :param commands:  format: [# ...], [], [pipes ....]
    :return: [], [parse tree ...]
    """
    if commands:
        if is_separator(commands[0]):   # if separator don;t look for pipes
            return []       # if first token is separator then no command to execute
        # pipes, commands = commands[0], commands[1:]
        pipes = commands.pop(0)     # get the first token
        if not is_pipes(pipes):     # the first token has to be a pipe symbol
            exit_error("Invalid syntax near `{}` {!s} expected pipes (|...).".format(pipes, commands))
        num_pipes = pipes_count(pipes)  # get the number of pipe operators
        piped_commands = []
        for i in range(1, num_pipes):
            piped_commands.append(parse(commands))  # obtain individual command parse trees
            if not commands:        # if unexpected end of command
                exit_error("Invalid syntax unexpected end of command.")
            # separator, commands = commands[0], commands[1:]
            separator = commands.pop(0)
            if not is_separator(separator):     # just to enforce syntax
                exit_error("Invalid syntax near {} expected #.".format(pipes))

        piped_commands.append(parse(commands))  # last one has no separator
        return piped_commands
    return []   # if no commands then return []


def parse(commands):
    """
    :param commands: format: [command ....], [command]
    :return: parse tree = (command, ), (command, [parse tree ...])
    """
    if commands:
        # If there are any commands
        # command, commands = commands[0], commands[1:]
        command = commands.pop(0)   # get the first command
        if not is_command(command):     # if unexpected string
            exit_error("Invalid syntax near {} expected a command.".format(command))
        piped_commands = parse_pipes(commands)      # get the piped commands

        return command, piped_commands      # return the constructed parse tree (Node, [children])
    exit_error("Invalid syntax expected command.")


"""
    This is the execution engine
    This function executes the given parse tree of commands
    parse tree: (command, [commands to pipe to])
"""


def execute(parse_tree):
    command, piped_commands = parse_tree    # get the command, and the commands to pipe to

    if not piped_commands:      # if no commands to pipe to
        execute_command(command)    # just execute the command

    read_fd, write_fd = os.pipe()   # else then create a pipe for command to write to
    if os.fork():                   # in the parent process
        os.close(read_fd)           # don;t need to read from pipe
        os.dup2(write_fd, 1)        # duplicate write end of pipe to stdout
        execute_command(command)    # execute the command
    else:                   # in child process
        os.close(write_fd)  # close the write end
        num_pipes = len(piped_commands)     # get the number of commands to pipe to
        if num_pipes == 1:  # if single piped command just use the existing pipe
            os.dup2(read_fd, 0)     # duplicate read end to stdin
            execute(piped_commands[0])  # execute that single command using the existing pipe
        else:   # else pipe network to dispatch the data
            pipe_fds = [os.pipe() for _ in range(num_pipes)]    # create all pipes required
            for i in range(num_pipes):      # now to execute each of individual commands
                if os.fork():               # in the parent
                    os.close(read_fd)       # close the original pipe so to read from pipe network
                    [os.close(pipe_fds[j][1]) for j in range(num_pipes)]    # close write fd of all pipes
                    [os.close(pipe_fds[j][0]) for j in range(num_pipes) if i != j]   # close all read except 1
                    os.dup2(pipe_fds[i][0], 0)  # duplicate that stdin
                    execute(piped_commands[i])  # execute that child command
            # Note: read from the pipe and write to all pipes (the process responsible for maintaining the pipe network)
            [os.close(pipe_fds[j][0]) for j in range(num_pipes)]  # close read fd of all pipes
            # Read from read end of pipe and write to pipe networks
            while True:
                read_data = os.read(read_fd, 100)   # <----- MODIFY BUFFER SIZE if needed
                if not read_data:
                    [os.close(pipe_fds[i][1]) for i in range(num_pipes)]    # close pipes ( Needed ? )
                    exit(0)     # exit if no more data to write
                [os.write(pipe_fds[i][1], read_data) for i in range(num_pipes)]     # write to network


# This function is to print the parse tree
def print_tree(tree, level=0):
    NUM_DASHES, NUM_SPACES = 4, 8
    if tree:
        command, piped_commands = tree
        print(" " * NUM_SPACES * level, "'", "-" * NUM_DASHES, command)
        [print_tree(piped_command, level+1) for piped_command in piped_commands]


input_parse_tree = parse(input_commands)    # parse the input commands
if print_parse_tree:
    print("\033[31mCOMMAND PARSE TREE:")    # Print the parse tree in color
    print_tree(input_parse_tree, 1)
    print("\033[0m")

out_read_fd, out_write_fd = os.pipe()       # we are using pipe to direct all stdout so as to know end of output
if not os.fork():                           # in the child process
    os.close(out_read_fd)                   # close read end
    os.dup2(out_write_fd, 1)                # duplicate write end to stdout
    execute(input_parse_tree)               # execute the command parse tree
else:
    os.close(out_write_fd)                  # close the write end in child
    while True:
        out_data = os.read(out_read_fd, 100)    # read from pipe
        if not out_data:                        # if no more data then break out of read loop
            break
        os.write(1, out_data)                   # write data to stdout
    print()     # just print a new line at the end of executing
