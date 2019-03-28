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
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler("dirwatcher.log")
    formatter = logging.Formatter(
        fmt="%(asctime)s %(msecs)03d %(name)s   %(levelname)s [%(threadName)s]: %(message)s",
        datefmt="%Y-%m-%d, %H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


logger = create_logger()  # this makes it a global var


def start_logger(logger, start_time):
    logger.info(
        "\n"
        "-------------------------------------------------------------------\n"
        "Running {}\n"
        "Started on {}\n"
        "-------------------------------------------------------------------\n"
        .format(__file__, start_time.isoformat())
    )


def stop_logger(logger, start_time):
    uptime = datetime.datetime.now() - start_time
    logger.info(
        "\n"
        "-------------------------------------------------------------------\n"
        "Stopped {}\n"
        "Uptime was {}\n"
        "-------------------------------------------------------------------\n"
        .format(__file__, str(uptime))
    )


def signal_handler(sig_num, frame):
    """
    This is a handler for SIGTERM and SIGINT. Other signals can be mapped here as well (SIGHUP?)
    Basically it just sets a global flag, and main() will exit it's loop if the signal is trapped.
    :param sig_num: The integer signal number that was trapped from the OS.
    :param frame: Not used
    :return None
    """
    # log the associated signal name (the python3 way)
    # logger.warning("Received {}".format(signal.Signals(sig_num).name))
    # log the signal name (the python2 way)
    signames = dict((k, v)
                    for v, k in reversed(sorted(signal.__dict__.items()))
                    if v.startswith("SIG") and not v.startswith("SIG_"))
    logger.warning("Received {}".format(signames[sig_num]))
    global exit_flag  # need to specify this as global in order to be used here
    exit_flag = True


def watch_directory(args, logger, dir_dict):
    # interval = args.interval
    directory = args.directory
    magic = args.magic
    extension = args.extension
    removed_files = []
    files = os.listdir(directory)
    # while True:
    #     try:
    #         logger.info("Inside watch loop")
    #         time.sleep(float(interval))
    #     except KeyboardInterrupt:
    #         break
    for file in files:
        if file not in dir_dict and file.endswith(extension):
            dir_dict[file] = 0
            logger.info("New file added: {}".format(file))
        full_path = os.path.join(directory, file)
        with open(full_path, "r") as read_opened_file:
            for counter, value in enumerate(read_opened_file, 1):
                if counter > dir_dict[file]:
                    dir_dict[file] = counter
                    if magic in value:
                        logger.info('"{}" found in "{}" on line {}'.format(
                            magic, file, counter))
    for key, value in dir_dict:
        if key not in files:
            logger.info(
                '"{0}" has left the building (a.k.a.: "{0}" was deleted)'.format(key))
            removed_files.append(key)
            dir_dict.pop(key)
    for file in removed_files:
        dir_dict.pop(value)
    # time.sleep(float(interval))


def create_parser():
    parser = argparse.ArgumentParser(
        description="Perform transformation on input text.")
    parser.add_argument("-d", "--directory",
                        help="enter directory to search within", default=".")
    parser.add_argument("-m", "--magic", help="enter magic text to search for")
    parser.add_argument("-e", "--extension",
                        help="enter file extension type to search within", default=".txt")
    parser.add_argument("-i", "--interval",
                        help="enter polling interval; based on seconds", default=1.0)
    return parser


def main(args):
    # global logger
    # logger = create_logger()
    parser = create_parser()
    if not args:
        parser.print_usage()
        sys.exit(1)
    args = parser.parse_args(args)
    start_time = datetime.datetime.now()
    # print(args)
    start_logger(logger, start_time)
    logger.info('Watching "{}" directory with ".{}" extensions for "{}" every {} seconds'.format(
        args.directory, args.extension, args.magic, args.interval))
    dir_dict = {}
    # Hook these two signals from the OS ..
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Now my signal_handler will get called if OS sends either of these to my process.
    while not exit_flag:
        try:
            # call my directory watching function..
            watch_directory(args, logger, dir_dict)
        except Exception as e:
            # This is an UNHANDLED exception
            # Log an ERROR level message here
            logger.error(e)
            # put a sleep inside my while loop so I don't peg the cpu usage at 100%
        time.sleep(float(args.interval))

    # final exit point happens here
    # Log a message that we are shutting down
    # Include the overall uptime since program start.
    stop_logger(logger, start_time)


if __name__ == "__main__":
    # global logger
    # example of cmdln: python dirwatcher.py
    main(sys.argv[1:])
    # main(sys.argv[1:], sys.argv[0])
    # main(sys.argv[0], sys.argv[1:])
    # main()
