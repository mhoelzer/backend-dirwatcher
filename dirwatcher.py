#!/usr/bin/env python

__author__ = "mhoelzer"


import argparse
import datetime
import time
import logging
import signal
import sys
import os


exit_flag = False


def create_logger():
    """making them logs because it's better than printing"""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler("dirwatcher.log")
    formatter = logging.Formatter(
        fmt=("%(asctime)s %(msecs)03d %(name)s %(levelname)s [%(threadName)s]:"
             " %(message)s"),
        datefmt="%Y-%m-%d, %H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


logger = create_logger()  # this makes it a global var


def start_banner(logger, start_time):
    """greeting text to the logger because we have manners"""
    logger.info(
        "\n"
        "-------------------------------------------------------------------\n"
        "Running {}\n"
        "Started on {}\n"
        "-------------------------------------------------------------------\n"
        .format(__file__, start_time)
    )


def stop_banner(logger, start_time):
    """farewell text to the logger because we have manners"""
    uptime = datetime.datetime.now() - start_time
    logger.info(
        "\n"
        "-------------------------------------------------------------------\n"
        "Stopped {}\n"
        "Uptime was {}\n"
        "Goodbye for now :)\n"
        "-------------------------------------------------------------------\n"
        .format(__file__, str(uptime))
    )


def signal_handler(sig_num, frame):
    """
    This is a handler for SIGTERM and SIGINT. Other signals can be mapped here
    as well (SIGHUP?). Basically it just sets a global flag, and main() will
    exit it's loop if the signal is trapped.
    :param sig_num: The integer signal number that was trapped from the OS.
    :param frame: Not used
    :return None
    """
    signames = dict((k, v)
                    for v, k in reversed(sorted(signal.__dict__.items()))
                    if v.startswith("SIG") and not v.startswith("SIG_"))
    logger.warning("Received {}".format(signames[sig_num]))
    global exit_flag  # need to specify this as global in order to be used here
    exit_flag = True


def find_magic_text(args, file, dir_dict):
    """finding the magic because magic is a magical thing"""
    # find magic with line and start num; return last line finished on
    directory = args.directory
    magic = args.magic
    full_path = os.path.join(directory, file)
    with open(full_path, "r") as read_opened_file:
        for line_num, line in enumerate(read_opened_file, 1):
            if line_num > dir_dict[file]:
                dir_dict[file] = line_num
                if magic in line:
                    logger.info('"{}" found in "{}" on line {}'.format(
                        magic, file, line_num))


def watch_directory(args, logger, dir_dict):
    """continuously watching the dir b/c you never know what might happen"""
    directory = args.directory
    extension = args.extension
    files = os.listdir(directory)
    for file in files:
        if file not in dir_dict and file.endswith(extension):
            dir_dict[file] = 0  # starting line number
            logger.info("New file added: {}".format(file))
        # if file not in dir_dict and not file.endswith(extension):
        #     continue
        find_magic_text(args, file, dir_dict)

    for key in list(dir_dict):  # makes copies of keys to iterate over
        if key not in files:
            logger.warning(
                'the file "{0}" has left the building (a.k.a.: "{0}"'
                'was deleted)'.format(key)
            )
            dir_dict.pop(key)

    logger.debug("Waiting in {}...".format(directory))  # debug level
    return file


def create_parser():
    """creates and returns an argparse cmd line option parser"""
    parser = argparse.ArgumentParser(
        description="Watching directory for magic text.")
    parser.add_argument("directory",
                        help="enter directory to search within", default=".")
    parser.add_argument("magic", help="enter magic text to search for")
    parser.add_argument("-e", "--extension",
                        help="enter file extension type to search within",
                        default=".txt")
    parser.add_argument("-i", "--interval",
                        help="enter polling interval; based on seconds",
                        default=1.0)
    return parser


def main(args):
    """runs all the stuff"""
    parser = create_parser()
    args = parser.parse_args(args)
    if not args:
        parser.print_usage()
        sys.exit(1)
    start_time = datetime.datetime.now()
    start_banner(logger, start_time)
    logger.info('Watching "{}" directory with ".{}" extensions for "{}" '
                'every {} seconds'.format(args.directory, args.extension,
                                          args.magic, args.interval))
    dir_dict = {}
    # Hook these two signals from the OS ..
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Now signal_handler will get called if OS sends either of these to process
    while not exit_flag:
        try:
            # call my directory watching function..
            watch_directory(args, logger, dir_dict)
        except Exception as e:
            # This is an UNHANDLED exception; Log an ERROR level message here
            # logger.exception(e)
            logger.error(str(e))
        # put a sleep inside my while loop so I don't peg the cpu usage at 100%
        time.sleep(float(args.interval))
    # final exit point happens here
    # Log a message that we are shutting down
    # Include the overall uptime since program start.
    stop_banner(logger, start_time)


if __name__ == "__main__":
    main(sys.argv[1:])
