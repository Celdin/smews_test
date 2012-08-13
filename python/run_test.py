#!/usr/bin/env python3

import sys, os
import signal
from modules import *

TEST_SUITES_FOLDER="test_suites"

# Handling of Ctrl+C
def sigint_handler(signum, frame):
    sys.stderr.write("Abording tests\n")
    Test.report(full=True)
    sys.exit(2)
################################################

class Test:
    __tests = []
    def begin(target, what):
        Test.__tests.append({"target": target, "what": what, "success": False, "why": "Unknow reason"})
    def success():
        Test.__tests[len(Test.__tests)-1]["success"] = True
        sys.stdout.write(".")
        sys.stdout.flush()
    def fail(message=None):
        if message:
            Test.__tests[len(Test.__tests)-1]["why"] = message
        sys.stdout.write("X")
        sys.stdout.flush()
    def report(full=False):
        print("")
        success = 0
        for test in Test.__tests:
            if not test["success"]:
                sys.stderr.write("FAIL   ({}): {} - {}\n".format(test["target"], test["what"], test["why"]))
            else:
                if full:
                    sys.stderr.write("SUCCESS({}): {}\n".format(test["target"], test["what"]))
                success = success + 1
        if not len(Test.__tests):
            print("No test performed")
        else:
            print("{}/{} tests passed ({:.2f} %)".format(success, len(Test.__tests), success / len(Test.__tests) * 100))
#####################################################



def get_smews_target_list():
    global smews_folder
    targets_folder = os.path.join(smews_folder,"targets")
    return system.get_subfolder_list(targets_folder)
#####################################################    

def get_test_suite_list():
    global script_folder
    global TEST_SUITES_FOLDER
    test_suite_folder = os.path.join(script_folder, TEST_SUITES_FOLDER);
    return system.get_subfolder_list(test_suite_folder)
#####################################################    


def perform_build(build_options):
    global smews_folder
    try:
        args = ["scons", "-c"]
        test_path = system.chdir(smews_folder)
        system.execute(args)
        args = ["scons"]
        for (option,value) in build_options.items():
            args.append("{}={}".format(option,value))
        system.execute(args)
    finally:
        system.chdir(test_path)
#####################################################

def test_build(test_suite, build_options):
    what = "build(test_suite: {} -- ip: {} -- ".format(test_suite, build_options["ipaddr"])
    if (build_options["disable"] == ""):
        what = what + "all options)"
    else:
        what = what + "disabled options: {})".format(build_options["disable"])
    Test.begin(build_options["target"], what)
    try:
        perform_build(build_options)
        Test.success()
    except system.ExecutionError as e:
        Test.fail(e.message)
#####################################################

    
def get_test_suite_folder(test_suite):
    global script_folder, TEST_SUITES_FOLDER
    test_suite_folder = os.path.join(os.path.join(script_folder, TEST_SUITES_FOLDER), test_suite)
    return test_suite_folder
####################################################


def get_targets_to_test(test_suite):
    test_suite_folder = get_test_suite_folder(test_suite)

    # target and notarget files
    target_file = os.path.join(test_suite_folder, "target")
    notarget_file = os.path.join(test_suite_folder, "notarget")

    # targets set
    smews_targets = set(get_smews_target_list())
    only_target_list = set(system.get_file_lines(target_file))
    no_target_list = set(system.get_file_lines(notarget_file))
    if len(only_target_list):
        return list((smews_targets & only_target_list) - no_target_list)
    else:
        return list(smews_targets - no_target_list)
####################################################        

def get_apps_to_include(test_suite):
    global smews_folder
    test_suite_folder = get_test_suite_folder(test_suite)
    apps_file = os.path.join(test_suite_folder, "useapps")
    apps_path = os.path.join(test_suite_folder, "apps")
    provided_apps = set(system.get_subfolder_list(apps_path))
    apps = set(system.get_file_lines(apps_file))
    smews_apps = set(system.get_subfolder_list(os.path.join(smews_folder, "apps")))
    return list(provided_apps | (apps & smews_apps))
####################################################

def get_smews_disable_options():
    global smews_folder
    return ['comet', 'post', 'timers', 'arguments', 'general_purpose_ip_handler']
#####################################################    

def get_options_combinations(options_list):
    if not options_list:
        return []
    if len(options_list) == 0:
        return []
    if len(options_list) == 1:
        return options_list
    if len(options_list) == 2:
        return [[options_list[0]],[options_list[1]], options_list]
    combinations = [[options_list[0]]]
    sub_comb = get_options_combinations(options_list[1:])
    for comb in  sub_comb:
        combinations.append(comb[:])
        comb.append(options_list[0])
        combinations.append(comb[:])
    return combinations
    
    
#####################################################

def get_disable_list(test_suite):
    test_suite_folder = get_test_suite_folder(test_suite)
    # files
    disable_file = os.path.join(test_suite_folder, "disable")
    nodisable_file = os.path.join(test_suite_folder, "nodisable")

    # sets
    smews_options = set(get_smews_disable_options())
    disable_options = set(system.get_file_lines(disable_file))
    nodisable_options = set(system.get_file_lines(nodisable_file))

    if len(disable_options):
        final_options_set = (smews_options & disable_options) - nodisable_options
    else:
        final_options_set = (smews_options) - nodisable_options
    combinations = get_options_combinations(list(final_options_set))
    combinations.append("")
    return combinations
####################################################

if len(sys.argv) < 2:
    sys.stderr.write("Usage: {0} <smews_folder> [target1 ... targetN]\n".format(sys.argv[0]))
    sys.exit(1)
else:
    smews_folder = sys.argv[1]
    targets_to_test = sys.argv[2:]

# Installing SIGINT handler
signal.signal(signal.SIGINT, sigint_handler)

script_folder = sys.path[0]

#targets=get_smews_target_list()
ips = ["192.168.100.200", "fc23::2"]

test_suites = get_test_suite_list()
for test_suite in test_suites:
    targets = get_targets_to_test(test_suite)
    if targets_to_test and len(targets_to_test):
        targets = list(set(targets) & set(targets_to_test))
    apps = get_apps_to_include(test_suite)
    disable_list = get_disable_list(test_suite)
    build_options = {}
    for target in targets:
        build_options["target"] = target
        for ip in ips:
            build_options["ipaddr"] = ip
            for disable in disable_list:
                build_options["disable"] = ",".join(disable)
                test_build(test_suite, build_options)
                #execute_test_suite(test_suite, build_options)
                

# for target in targets:
#     for ip in ips:
#         test_target(target, ip)

Test.report(True)