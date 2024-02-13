#!/usr/bin/env python3

# Script by Ben Limmer
# https://github.com/l1m5
#
# This Python script will combine all the host files you provide
# as sources into one, unique host file to keep your internet browsing happy.

import argparse
import fnmatch
import ipaddress
import json
import locale
import os
import re
import shutil
import sys
import tempfile
import time
from glob import glob
from typing import Optional, Tuple

# Detecting Python 3 for version-dependent implementations
PY3 = sys.version_info >= (3, 0)

if not PY3:
    raise Exception("We do not support Python 2 anymore.")


try:
    import requests
except ImportError:
    raise ImportError(
        "This project's dependencies have changed. The Requests library ("
        "https://docs.python-requests.org/en/latest/) is now required."
    )


# Project Settings
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))


def get_defaults():
    """
    Helper method for getting the default settings.

    Returns
    -------
    default_settings : dict
        A dictionary of the default settings when updating host information.
    """

    return {
        "numberofrules": 0,
        "datapath": path_join_robust(BASEDIR_PATH, "data"),
        "freshen": True,
        "replace": False,
        "backup": False,
        "keepdomaincomments": True,
        "nounifiedhosts": False,
        "compress": False,
        "minimise": False,
        "outputsubfolder": "",
        "hostfilename": "hosts",
        "targetip": "0.0.0.0",
        "sourcedatafilename": "update.json",
        "sourcesdata": [],
        "exclusionpattern": r"([a-zA-Z\d-]+\.){0,}",
        "exclusionregexes": [],
        "exclusions": [],
        "commonexclusions": [],
        "blacklistfile": path_join_robust(BASEDIR_PATH, "blacklist"),
        "whitelistfile": path_join_robust(BASEDIR_PATH, "whitelist"),
    }


# End Project Settings


def main():
    parser = argparse.ArgumentParser(
        description="Creates a unified hosts "
        "file from hosts stored in the data subfolders."
    )
    parser.add_argument(
        "--auto",
        "-a",
        dest="auto",
        default=False,
        action="store_true",
        help="Run without prompting.",
    )
    parser.add_argument(
        "--backup",
        "-b",
        dest="backup",
        default=False,
        action="store_true",
        help="Backup the hosts files before they are overridden.",
    )
    parser.add_argument(
        "--nounifiedhosts",
        dest="nounifiedhosts",
        default=False,
        action="store_true",
        help="Do not include the unified hosts file in the final hosts file.",
    )
    parser.add_argument(
        "--ip",
        "-i",
        dest="targetip",
        default="0.0.0.0",
        help="Target IP address. Default is 0.0.0.0.",
    )
    parser.add_argument(
        "--keepdomaincomments",
        "-k",
        dest="keepdomaincomments",
        action="store_false",
        default=True,
        help="Do not keep domain line comments.",
    )
    parser.add_argument(
        "--noupdate",
        "-n",
        dest="noupdate",
        default=False,
        action="store_true",
        help="Don't update from host data sources.",
    )
    parser.add_argument(
        "--nogendata",
        "-g",
        dest="nogendata",
        default=False,
        action="store_true",
        help="Skip generation of readmeData.json",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="outputsubfolder",
        default="",
        help="Output subfolder for generated hosts file.",
    )
    parser.add_argument(
        "--replace",
        "-r",
        dest="replace",
        default=False,
        action="store_true",
        help="Replace your active hosts file with this new hosts file.",
    )
    parser.add_argument(
        "--flush-dns-cache",
        "-f",
        dest="flushdnscache",
        default=False,
        action="store_true",
        help="Attempt to flush DNS cache after replacing the hosts file.",
    )
    parser.add_argument(
        "--compress",
        "-c",
        dest="compress",
        default=False,
        action="store_true",
        help="Compress the hosts file ignoring non-necessary lines "
        "(empty lines and comments) and putting multiple domains in "
        "each line. Improve the performance under Windows.",
    )
    parser.add_argument(
        "--minimise",
        "-m",
        dest="minimise",
        default=False,
        action="store_true",
        help="Minimise the hosts file ignoring non-necessary lines "
        "(empty lines and comments).",
    )
    parser.add_argument(
        "--whitelist",
        "-w",
        dest="whitelistfile",
        default=path_join_robust(BASEDIR_PATH, "whitelist"),
        help="Whitelist file to use while generating hosts files.",
    )
    parser.add_argument(
        "--blacklist",
        "-x",
        dest="blacklistfile",
        default=path_join_robust(BASEDIR_PATH, "blacklist"),
        help="Blacklist file to use while generating hosts files.",
    )

    global settings

    options = vars(parser.parse_args())

    options["outputpath"] = path_join_robust(BASEDIR_PATH, options["outputsubfolder"])
    options["freshen"] = not options["noupdate"]

    settings = get_defaults()
    settings.update(options)

    data_path = settings["datapath"]

    settings["sources"] = list_dir_no_hidden(data_path)

    auto = settings["auto"]
    exclusion_regexes = settings["exclusionregexes"]
    source_data_filename = settings["sourcedatafilename"]
    no_unified_hosts = settings["nounifiedhosts"]

    update_sources = prompt_for_update(freshen=settings["freshen"], update_auto=auto)
    if update_sources:
        update_all_sources(source_data_filename, settings["hostfilename"])

    gather_exclusions = prompt_for_exclusions(skip_prompt=auto)

    if gather_exclusions:
        common_exclusions = settings["commonexclusions"]
        exclusion_pattern = settings["exclusionpattern"]
        exclusion_regexes = display_exclusion_options(
            common_exclusions=common_exclusions,
            exclusion_pattern=exclusion_pattern,
            exclusion_regexes=exclusion_regexes,
        )

    merge_file = create_initial_file(
        nounifiedhosts=no_unified_hosts,
    )
    remove_old_hosts_file(settings["outputpath"], "hosts", settings["backup"])
    if settings["compress"]:
        final_file = open(path_join_robust(settings["outputpath"], "hosts"), "w+b")
        compressed_file = tempfile.NamedTemporaryFile()
        remove_dups_and_excl(merge_file, exclusion_regexes, compressed_file)
        compress_file(compressed_file, settings["targetip"], final_file)
    elif settings["minimise"]:
        final_file = open(path_join_robust(settings["outputpath"], "hosts"), "w+b")
        minimised_file = tempfile.NamedTemporaryFile()
        remove_dups_and_excl(merge_file, exclusion_regexes, minimised_file)
        minimise_file(minimised_file, settings["targetip"], final_file)
    else:
        final_file = remove_dups_and_excl(merge_file, exclusion_regexes)

    number_of_rules = settings["numberofrules"]
    output_subfolder = settings["outputsubfolder"]

    write_opening_header(
        final_file,
        numberofrules=number_of_rules,
        outputsubfolder=output_subfolder,
        nounifiedhosts=no_unified_hosts,
    )
    final_file.close()

    print_success(
        "Success! The hosts file has been saved in folder "
        + output_subfolder
        + "\nIt contains "
        + "{:,}".format(number_of_rules)
        + " unique entries."
    )


# Prompt the User
def prompt_for_update(freshen, update_auto):
    """
    Prompt the user to update all hosts files.

    If requested, the function will update all data sources after it
    checks that a hosts file does indeed exist.

    Parameters
    ----------
    freshen : bool
        Whether data sources should be updated. This function will return
        if it is requested that data sources not be updated.
    update_auto : bool
        Whether or not to automatically update all data sources.

    Returns
    -------
    update_sources : bool
        Whether or not we should update data sources for exclusion files.
    """

    # Create a hosts file if it doesn't exist.
    hosts_file = path_join_robust(BASEDIR_PATH, "hosts")

    if not os.path.isfile(hosts_file):
        try:
            open(hosts_file, "w+").close()
        except (IOError, OSError):
            # Starting in Python 3.3, IOError is aliased
            # OSError. However, we have to catch both for
            # Python 2.x failures.
            print_failure(
                "ERROR: No 'hosts' file in the folder. Try creating one manually."
            )

    if not freshen:
        return False

    prompt = "Do you want to update all data sources?"

    if update_auto or query_yes_no(prompt):
        return True
    elif not update_auto:
        print("OK, we'll stick with what we've got locally.")

    return False


def prompt_for_exclusions(skip_prompt):
    """
    Prompt the user to exclude any custom domains from being blocked.

    Parameters
    ----------
    skip_prompt : bool
        Whether or not to skip prompting for custom domains to be excluded.
        If true, the function returns immediately.

    Returns
    -------
    gather_exclusions : bool
        Whether or not we should proceed to prompt the user to exclude any
        custom domains beyond those in the whitelist.
    """

    prompt = ("Do you want to exclude any domains?")

    if not skip_prompt:
        if query_yes_no(prompt):
            return True
        else:
            print("OK, we'll only exclude domains in the whitelist.")

    return False


def sort_sources(sources):
    """
    Sorts the sources.
    The idea is that all Steven Black's list, file or entries
    get on top and the rest sorted alphabetically.

    Parameters
    ----------
    sources: list
        The sources to sort.
    """

    result = sorted(
        sources.copy(),
        key=lambda x: x.lower().replace("-", "").replace("_", "").replace(" ", ""),
    )

    # Steven Black's repositories/files/lists should be on top!
    steven_black_positions = [
        x for x, y in enumerate(result) if "placidina" in y.lower()
    ]

    for index in steven_black_positions:
        result.insert(0, result.pop(index))

    return result


# Exclusion logic
def display_exclusion_options(common_exclusions, exclusion_pattern, exclusion_regexes):
    """
    Display the exclusion options to the user.

    This function checks whether a user wants to exclude particular domains,
    and if so, excludes them.

    Parameters
    ----------
    common_exclusions : list
        A list of common domains that are excluded from being blocked. One
        example is Hulu. This setting is set directly in the script and cannot
        be overwritten by the user.
    exclusion_pattern : str
        The exclusion pattern with which to create the domain regex.
    exclusion_regexes : list
        The list of regex patterns used to exclude domains.

    Returns
    -------
    aug_exclusion_regexes : list
        The original list of regex patterns potentially with additional
        patterns from domains that the user chooses to exclude.
    """

    for exclusion_option in common_exclusions:
        prompt = "Do you want to exclude the domain " + exclusion_option + " ?"

        if query_yes_no(prompt):
            exclusion_regexes = exclude_domain(
                exclusion_option, exclusion_pattern, exclusion_regexes
            )
        else:
            continue

    exclusion_regexes = gather_custom_exclusions(
        exclusion_pattern, exclusion_regexes
    )

    return exclusion_regexes


def gather_custom_exclusions(exclusion_pattern, exclusion_regexes):
    """
    Gather custom exclusions from the user.

    Parameters
    ----------
    exclusion_pattern : str
        The exclusion pattern with which to create the domain regex.
    exclusion_regexes : list
        The list of regex patterns used to exclude domains.

    Returns
    -------
    aug_exclusion_regexes : list
        The original list of regex patterns potentially with additional
        patterns from domains that the user chooses to exclude.
    """

    # We continue running this while-loop until the user
    # says that they have no more domains to exclude.
    while True:
        domain_prompt = "Enter the domain you want to exclude (e.g. facebook.com): "
        user_domain = input(domain_prompt)

        if is_valid_user_provided_domain_format(user_domain):
            exclusion_regexes = exclude_domain(
                user_domain, exclusion_pattern, exclusion_regexes
            )

        continue_prompt = "Do you have more domains you want to enter?"
        if not query_yes_no(continue_prompt):
            break

    return exclusion_regexes


def exclude_domain(domain, exclusion_pattern, exclusion_regexes):
    """
    Exclude a domain from being blocked.

    This creates the domain regex by which to exclude this domain and appends
    it a list of already-existing exclusion regexes.

    Parameters
    ----------
    domain : str
        The filename or regex pattern to exclude.
    exclusion_pattern : str
        The exclusion pattern with which to create the domain regex.
    exclusion_regexes : list
        The list of regex patterns used to exclude domains.

    Returns
    -------
    aug_exclusion_regexes : list
        The original list of regex patterns with one additional pattern from
        the `domain` input.
    """

    exclusion_regex = re.compile(exclusion_pattern + domain)
    exclusion_regexes.append(exclusion_regex)

    return exclusion_regexes


def matches_exclusions(stripped_rule, exclusion_regexes):
    """
    Check whether a rule matches an exclusion rule we already provided.

    If this function returns True, that means this rule should be excluded
    from the final hosts file.

    Parameters
    ----------
    stripped_rule : str
        The rule that we are checking.
    exclusion_regexes : list
        The list of regex patterns used to exclude domains.

    Returns
    -------
    matches_exclusion : bool
        Whether or not the rule string matches a provided exclusion.
    """

    try:
        stripped_domain = stripped_rule.split()[1]
    except IndexError:
        # Example: 'example.org' instead of '0.0.0.0 example.org'
        stripped_domain = stripped_rule

    for exclusionRegex in exclusion_regexes:
        if exclusionRegex.search(stripped_domain):
            return True

    return False


# End Exclusion Logic


# Update Logic
def update_sources_data(sources_data, **sources_params):
    """
    Update the sources data and information for each source.

    Parameters
    ----------
    sources_data : list
        The list of sources data that we are to update.
    sources_params : kwargs
        Dictionary providing additional parameters for updating the
        sources data. Currently, those fields are:

        1) datapath
        4) sourcedatafilename
        5) nounifiedhosts

    Returns
    -------
    update_sources_data : list
        The original source data list with new source data appended.
    """

    source_data_filename = sources_params["sourcedatafilename"]

    if not sources_params["nounifiedhosts"]:
        for source in sort_sources(
            recursive_glob(sources_params["datapath"], source_data_filename)
        ):
            update_file = open(source, "r", encoding="UTF-8")
            try:
                update_data = json.load(update_file)
                sources_data.append(update_data)
            finally:
                update_file.close()

    return sources_data


def jsonarray(json_array_string):
    """
    Transformer, converts a json array string hosts into one host per
    line, prefixing each line with "127.0.0.1 ".

    Parameters
    ----------
    json_array_string : str
        The json array string in the form
          '["example1.com", "example1.com", ...]'
    """

    temp_list = json.loads(json_array_string)
    hostlines = "127.0.0.1 " + "\n127.0.0.1 ".join(temp_list)
    return hostlines


def update_all_sources(source_data_filename, host_filename):
    """
    Update all host files, regardless of folder depth.

    Parameters
    ----------
    source_data_filename : str
        The name of the filename where information regarding updating
        sources for a particular URL is stored. This filename is assumed
        to be the same for all sources.
    host_filename : str
        The name of the file in which the updated source information
        is stored for a particular URL. This filename is assumed to be
        the same for all sources.
    """

    # The transforms we support
    transform_methods = {"jsonarray": jsonarray}

    all_sources = sort_sources(recursive_glob("*", source_data_filename))

    for source in all_sources:
        update_file = open(source, "r", encoding="UTF-8")
        update_data = json.load(update_file)
        update_file.close()

        # we can pause updating any given hosts source.
        # if the update.json "pause" key is missing, don't pause.
        if update_data.get("pause", False):
            continue

        update_url = update_data["url"]
        update_transforms = update_data.get("transforms", [])

        print("Updating source " + os.path.dirname(source) + " from " + update_url)

        try:
            updated_file = get_file_by_url(update_url)

            # spin the transforms as required
            for transform in update_transforms:
                updated_file = transform_methods[transform](updated_file)

            # get rid of carriage-return symbols
            updated_file = updated_file.replace("\r", "")

            hosts_file_path = os.path.join(BASEDIR_PATH, os.path.dirname(source), host_filename)
            with open(hosts_file_path, "wb") as hosts_file:
                write_data(hosts_file, updated_file)
        except Exception as e:
            print(f"Error in updating source {update_url}: {e}")


# End Update Logic


# File Logic
def create_initial_file(**initial_file_params):
    """
    Initialize the file in which we merge all host files for later pruning.

    Parameters
    ----------
    header_params : kwargs
        Dictionary providing additional parameters for populating the initial file
        information. Currently, those fields are:

        1) nounifiedhosts
    """

    merge_file = tempfile.NamedTemporaryFile()

    if not initial_file_params["nounifiedhosts"]:
        # spin the sources for the base file
        for source in sort_sources(
            recursive_glob(settings["datapath"], settings["hostfilename"])
        ):
            start = "# Start {}\n\n".format(os.path.basename(os.path.dirname(source)))
            end = "\n# End {}\n\n".format(os.path.basename(os.path.dirname(source)))

            with open(source, "r", encoding="UTF-8") as curFile:
                write_data(merge_file, start + curFile.read() + end)

    if os.path.isfile(settings["blacklistfile"]):
        with open(settings["blacklistfile"], "r") as curFile:
            write_data(merge_file, curFile.read())

    return merge_file


def compress_file(input_file, target_ip, output_file):
    """
    Reduce the file dimension removing non-necessary lines (empty lines and
    comments) and putting multiple domains in each line.
    Reducing the number of lines of the file, the parsing under Microsoft
    Windows is much faster.

    Parameters
    ----------
    input_file : file
        The file object that contains the hostnames that we are reducing.
    target_ip : str
        The target IP address.
    output_file : file
        The file object that will contain the reduced hostnames.
    """

    input_file.seek(0)  # reset file pointer
    write_data(output_file, "\n")

    target_ip_len = len(target_ip)
    lines = [target_ip]
    lines_index = 0
    for line in input_file.readlines():
        line = line.decode("UTF-8")

        if line.startswith(target_ip):
            if lines[lines_index].count(" ") < 9:
                lines[lines_index] += (
                    " " + line[target_ip_len : line.find("#")].strip()  # noqa: E203
                )
            else:
                lines[lines_index] += "\n"
                lines.append(line[: line.find("#")].strip())
                lines_index += 1

    for line in lines:
        write_data(output_file, line)

    input_file.close()


def minimise_file(input_file, target_ip, output_file):
    """
    Reduce the file dimension removing non-necessary lines (empty lines and
    comments).

    Parameters
    ----------
    input_file : file
        The file object that contains the hostnames that we are reducing.
    target_ip : str
        The target IP address.
    output_file : file
        The file object that will contain the reduced hostnames.
    """

    input_file.seek(0)  # reset file pointer
    write_data(output_file, "\n")

    lines = []
    for line in input_file.readlines():
        line = line.decode("UTF-8")

        if line.startswith(target_ip):
            lines.append(line[: line.find("#")].strip() + "\n")

    for line in lines:
        write_data(output_file, line)

    input_file.close()


def remove_dups_and_excl(merge_file, exclusion_regexes, output_file=None):
    """
    Remove duplicates and remove hosts that we are excluding.

    We check for duplicate hostnames as well as remove any hostnames that
    have been explicitly excluded by the user.

    Parameters
    ----------
    merge_file : file
        The file object that contains the hostnames that we are pruning.
    exclusion_regexes : list
        The list of regex patterns used to exclude domains.
    output_file : file
        The file object in which the result is written. If None, the file
        'settings["outputpath"]' will be created.
    """

    number_of_rules = settings["numberofrules"]

    if os.path.isfile(settings["whitelistfile"]):
        with open(settings["whitelistfile"], "r") as ins:
            for line in ins:
                line = line.strip(" \t\n\r")
                if line and not line.startswith("#"):
                    settings["exclusions"].append(line)

    if not os.path.exists(settings["outputpath"]):
        os.makedirs(settings["outputpath"])

    if output_file is None:
        final_file = open(path_join_robust(settings["outputpath"], "hosts"), "w+b")
    else:
        final_file = output_file

    merge_file.seek(0)  # reset file pointer
    hostnames = {"localhost", "localhost.localdomain", "local", "broadcasthost"}
    exclusions = settings["exclusions"]

    for line in merge_file.readlines():
        write_line = True

        # Explicit encoding
        line = line.decode("UTF-8")

        # replace tabs with space
        line = line.replace("\t+", " ")

        # see gh-271: trim trailing whitespace, periods
        line = line.rstrip(" .")

        # Testing the first character doesn't require startswith
        if line[0] == "#" or re.match(r"^\s*$", line[0]):
            write_data(final_file, line)
            continue
        if "::1" in line:
            continue

        stripped_rule = strip_rule(line)  # strip comments
        if not stripped_rule or matches_exclusions(stripped_rule, exclusion_regexes):
            continue

        # Issue #1628
        if "@" in stripped_rule:
            continue

        # Normalize rule
        hostname, normalized_rule = normalize_rule(
            stripped_rule,
            target_ip=settings["targetip"],
            keep_domain_comments=settings["keepdomaincomments"],
        )

        for exclude in exclusions:
            if re.search(r"(^|[\s\.])" + re.escape(exclude) + r"\s", line):
                write_line = False
                break

        if normalized_rule and (hostname not in hostnames) and write_line:
            write_data(final_file, normalized_rule)
            hostnames.add(hostname)
            number_of_rules += 1

    settings["numberofrules"] = number_of_rules
    merge_file.close()

    if output_file is None:
        return final_file


def normalize_rule(rule, target_ip, keep_domain_comments):
    """
    Standardize and format the rule string provided.

    Parameters
    ----------
    rule : str
        The rule whose spelling and spacing we are standardizing.
    target_ip : str
        The target IP address for the rule.
    keep_domain_comments : bool
        Whether or not to keep comments regarding these domains in
        the normalized rule.

    Returns
    -------
    normalized_rule : tuple
        A tuple of the hostname and the rule string with spelling
        and spacing reformatted.
    """

    def normalize_response(
        extracted_hostname: str, extracted_suffix: Optional[str]
    ) -> Tuple[str, str]:
        """
        Normalizes the responses after the provision of the extracted
        hostname and suffix - if exist.

        Parameters
        ----------
        extracted_hostname: str
            The extracted hostname to work with.
        extracted_suffix: str
            The extracted suffix to with.

        Returns
        -------
        normalized_response: tuple
            A tuple of the hostname and the rule string with spelling
            and spacing reformatted.
        """

        rule = "%s %s" % (target_ip, extracted_hostname)

        if keep_domain_comments and extracted_suffix:
            if not extracted_suffix.strip().startswith("#"):
                # Strings are stripped, therefore we need to add the space back.
                rule += " # %s" % extracted_suffix
            else:
                rule += " %s" % extracted_suffix

        return extracted_hostname, rule + "\n"

    def is_ip(dataset: str) -> bool:
        """
        Checks whether the given dataset is an IP.

        Parameters
        ----------

        dataset: str
            The dataset to work with.

        Returns
        -------
        is_ip: bool
            Whether the dataset is an IP.
        """

        try:
            _ = ipaddress.ip_address(dataset)
            return True
        except ValueError:
            return False

    def belch_unwanted(unwanted: str) -> Tuple[None, None]:
        """
        Belches unwanted to screen.

        Parameters
        ----------
        unwanted: str
            The unwanted string to belch.

        Returns
        -------
        belched: tuple
            A tuple of None, None.
        """

        """
        finally, if we get here, just belch to screen
        """
        print("==>%s<==" % unwanted)
        return None, None

    """
    first try: IP followed by domain
    """

    static_ip_regex = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    split_rule = rule.split(maxsplit=1)

    if is_ip(split_rule[0]):
        # Assume that the first item is an IP address following the rule.

        if " " or "\t" in split_rule[-1]:
            try:
                # Example: 0.0.0.0 example.org # hello, world!
                hostname, suffix = split_rule[-1].split(maxsplit=1)
            except ValueError:
                # Example: 0.0.0.0 example.org[:space:]
                hostname, suffix = split_rule[-1], None
        else:
            # Example: 0.0.0.0 example.org
            hostname, suffix = split_rule[-1], None

        hostname = hostname.lower()

        if (
            is_ip(hostname)
            or re.search(static_ip_regex, hostname)
            or "." not in hostname
            or "/" in hostname
            or ".." in hostname
            or ":" in hostname
        ):
            # Example: 0.0.0.0 127.0.0.1

            # If the hostname is:
            #   - an IP - or looks like it,
            #   - doesn't contain dots, or
            #   - contains a colon,
            # we don't want to normalize it.
            return belch_unwanted(rule)

        return normalize_response(hostname, suffix)

    if (
        not re.search(static_ip_regex, split_rule[0])
        and ":" not in split_rule[0]
        and ".." not in split_rule[0]
        and "/" not in split_rule[0]
        and "." in split_rule[0]
    ):
        # Deny anything that looks like an IP; doesn't container dots or INVALID.

        try:
            hostname, suffix = split_rule
        except ValueError:
            hostname, suffix = split_rule[0], None

        hostname = hostname.lower()

        return normalize_response(hostname, suffix)

    return belch_unwanted(rule)


def strip_rule(line):
    """
    Sanitize a rule string provided before writing it to the output hosts file.

    Parameters
    ----------
    line : str
        The rule provided for sanitation.

    Returns
    -------
    sanitized_line : str
        The sanitized rule.
    """

    return " ".join(line.split())


def write_opening_header(final_file, **header_params):
    """
    Write the header information into the newly-created hosts file.

    Parameters
    ----------
    final_file : file
        The file object that points to the newly-created hosts file.
    header_params : kwargs
        Dictionary providing additional parameters for populating the header
        information. Currently, those fields are:

        2) numberofrules
        3) outputsubfolder
        5) nounifiedhosts
    """

    final_file.seek(0)  # Reset file pointer.
    file_contents = final_file.read()  # Save content.

    final_file.seek(0)  # Write at the top.

    write_data(
        final_file,
        "# Title: Placidina/PrivacyBlackList\n#\n"
        "# This hosts file is a merged collection "
        "of hosts from reputable sources,\n",
    )
    write_data(final_file, "# with a dash of crowd sourcing via GitHub\n#\n")
    write_data(
        final_file,
        "# Date: " + time.strftime("%d %B %Y %H:%M:%S (%Z)", time.gmtime()) + "\n",
    )

    write_data(
        final_file,
        (
            "# Number of unique domains: {:,}\n#\n".format(
                header_params["numberofrules"]
            )
        ),
    )
    write_data(
        final_file,
        "# Fetch the latest version of this file: "
        "https://raw.githubusercontent.com/Placidina/PrivacyBlackList/master/"
        + path_join_robust(header_params["outputsubfolder"], "").replace("\\", "/")
        + "hosts\n",
    )
    write_data(
        final_file, "# Project home page: https://github.com/Placidina/PrivacyBlackList\n"
    )
    write_data(
        final_file,
        "# Project releases: https://github.com/Placidina/PrivacyBlackList/releases\n#\n",
    )
    write_data(
        final_file,
        "# ===============================================================\n",
    )
    write_data(final_file, "\n")

    final_file.write(file_contents)


def remove_old_hosts_file(path_to_file, file_name, backup):
    """
    Remove the old hosts file.

    This is a hotfix because merging with an already existing hosts file leads
    to artifacts and duplicates.

    Parameters
    ----------
    backup : boolean, default False
        Whether or not to backup the existing hosts file.
    """

    full_file_path = path_join_robust(path_to_file, file_name)

    if os.path.exists(full_file_path):
        if backup:
            backup_file_path = full_file_path + "-{}".format(
                time.strftime("%Y-%m-%d-%H-%M-%S")
            )

            # Make a backup copy, marking the date in which the list was updated
            shutil.copy(full_file_path, backup_file_path)

        os.remove(full_file_path)

    # Create directory if not exists
    if not os.path.exists(path_to_file):
        os.makedirs(path_to_file)

    # Create new empty hosts file
    open(full_file_path, "a").close()


# End File Logic


def domain_to_idna(line):
    """
    Encode a domain that is present into a line into `idna`. This way we
    avoid most encoding issues.

    Parameters
    ----------
    line : str
        The line we have to encode/decode.

    Returns
    -------
    line : str
        The line in a converted format.

    Notes
    -----
    - This function encodes only the domain to `idna` format because in
        most cases, the encoding issue is due to a domain which looks like
        `b'\xc9\xa2oogle.com'.decode('idna')`.
    - About the splitting:
        We split because we only want to encode the domain and not the full
        line, which may cause some issues. Keep in mind that we split, but we
        still concatenate once we encoded the domain.

        - The following split the prefix `0.0.0.0` or `127.0.0.1` of a line.
        - The following also split the trailing comment of a given line.
    """

    if not line.startswith("#"):
        tabs = "\t"
        space = " "

        tabs_position, space_position = (line.find(tabs), line.find(space))

        if tabs_position > -1 and space_position > -1:
            if space_position < tabs_position:
                separator = space
            else:
                separator = tabs
        elif not tabs_position == -1:
            separator = tabs
        elif not space_position == -1:
            separator = space
        else:
            separator = ""

        if separator:
            splited_line = line.split(separator)

            try:
                index = 1
                while index < len(splited_line):
                    if splited_line[index]:
                        break
                    index += 1

                if "#" in splited_line[index]:
                    index_comment = splited_line[index].find("#")

                    if index_comment > -1:
                        comment = splited_line[index][index_comment:]

                        splited_line[index] = (
                            splited_line[index]
                            .split(comment)[0]
                            .encode("IDNA")
                            .decode("UTF-8")
                            + comment
                        )

                splited_line[index] = splited_line[index].encode("IDNA").decode("UTF-8")
            except IndexError:
                pass
            return separator.join(splited_line)
        return line.encode("IDNA").decode("UTF-8")
    return line.encode("UTF-8").decode("UTF-8")


def get_file_by_url(url, params=None, **kwargs):
    """
    Retrieve the contents of the hosts file at the URL, then pass it through domain_to_idna().

    Parameters are passed to the requests.get() function.

    Parameters
    ----------
    url : str or bytes
        URL for the new Request object.
    params :
        Dictionary, list of tuples or bytes to send in the query string for the Request.
    kwargs :
        Optional arguments that request takes.

    Returns
    -------
    url_data : str or None
        The data retrieved at that URL from the file. Returns None if the
        attempted retrieval is unsuccessful.
    """

    try:
        req = requests.get(url=url, params=params, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving data from {url}: {e}")
        return None

    req.encoding = req.apparent_encoding
    res_text = "\n".join([domain_to_idna(line) for line in req.text.split("\n")])
    return res_text


def write_data(f, data):
    """
    Write data to a file object.

    Parameters
    ----------
    f : file
        The file object at which to write the data.
    data : str
        The data to write to the file.
    """

    f.write(data.encode("UTF-8"))


def list_dir_no_hidden(path):
    """
    List all files in a directory, except for hidden files.

    Parameters
    ----------
    path : str
        The path of the directory whose files we wish to list.
    """

    return glob(os.path.join(path, "*"))


def query_yes_no(question, default="yes"):
    """
    Ask a yes/no question via input() and get answer from the user.

    Inspired by the following implementation:

    https://code.activestate.com/recipes/577058/

    Parameters
    ----------
    question : str
        The question presented to the user.
    default : str, default "yes"
        The presumed answer if the user just hits <Enter>. It must be "yes",
        "no", or None (means an answer is required of the user).

    Returns
    -------
    yes : Whether or not the user replied yes to the question.
    """

    valid = {"yes": "yes", "y": "yes", "ye": "yes", "no": "no", "n": "no"}
    prompt = {None: " [y/n] ", "yes": " [Y/n] ", "no": " [y/N] "}.get(default, None)

    if not prompt:
        raise ValueError("invalid default answer: '%s'" % default)

    reply = None

    while not reply:
        sys.stdout.write(colorize(question, Colors.PROMPT) + prompt)

        choice = input().lower()
        reply = None

        if default and not choice:
            reply = default
        elif choice in valid:
            reply = valid[choice]
        else:
            print_failure("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

    return reply == "yes"


def is_valid_user_provided_domain_format(domain):
    """
    Check whether a provided domain is valid.

    Parameters
    ----------
    domain : str
        The domain against which to check.

    Returns
    -------
    valid_domain : bool
        Whether or not the domain provided is valid.
    """

    if domain == "":
        print("You didn't enter a domain. Try again.")
        return False

    domain_regex = re.compile(r"www\d{0,3}[.]|https?")

    if domain_regex.match(domain):
        print(
            "The domain " + domain + " is not valid. Do not include "
            "www.domain.com or http(s)://domain.com. Try again."
        )
        return False
    else:
        return True


def recursive_glob(stem, file_pattern):
    """
    Recursively match files in a directory according to a pattern.

    Parameters
    ----------
    stem : str
        The directory in which to recurse
    file_pattern : str
        The filename regex pattern to which to match.

    Returns
    -------
    matches_list : list
        A list of filenames in the directory that match the file pattern.
    """

    if sys.version_info >= (3, 5):
        return glob(stem + "/**/" + file_pattern, recursive=True)
    else:
        # gh-316: this will avoid invalid unicode comparisons in Python 2.x
        if stem == str("*"):
            stem = "."
        matches = []
        for root, dirnames, filenames in os.walk(stem):
            for filename in fnmatch.filter(filenames, file_pattern):
                matches.append(path_join_robust(root, filename))
    return matches


def path_join_robust(path, *paths):
    """
    Wrapper around `os.path.join` with handling for locale issues.

    Parameters
    ----------
    path : str
        The first path to join.
    paths : varargs
        Subsequent path strings to join.

    Returns
    -------
    joined_path : str
        The joined path string of the two path inputs.

    Raises
    ------
    locale.Error : A locale issue was detected that prevents path joining.
    """

    try:
        # gh-316: joining unicode and str can be saddening in Python 2.x
        path = str(path)
        paths = [str(another_path) for another_path in paths]

        return os.path.join(path, *paths)
    except UnicodeDecodeError as e:
        raise locale.Error(
            "Unable to construct path. This is likely a LOCALE issue:\n\n" + str(e)
        )


# Colors
class Colors(object):
    PROMPT = "\033[94m"
    SUCCESS = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


def supports_color():
    """
    Check whether the running terminal or command prompt supports color.

    Inspired by StackOverflow link (and Django implementation) here:

    https://stackoverflow.com/questions/7445658

    Returns
    -------
    colors_supported : bool
        Whether the running terminal or command prompt supports color.
    """

    sys_platform = sys.platform
    supported = sys_platform != "Pocket PC" and (
        sys_platform != "win32" or "ANSICON" in os.environ
    )

    atty_connected = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return supported and atty_connected


def colorize(text, color):
    """
    Wrap a string so that it displays in a particular color.

    This function adds a prefix and suffix to a text string so that it is
    displayed as a particular color, either in command prompt or the terminal.

    If the running terminal or command prompt does not support color, the
    original text is returned without being wrapped.

    Parameters
    ----------
    text : str
        The message to display.
    color : str
        The color string prefix to put before the text.

    Returns
    -------
    wrapped_str : str
        The wrapped string to display in color, if possible.
    """

    if not supports_color():
        return text

    return color + text + Colors.ENDC


def print_success(text):
    """
    Print a success message.

    Parameters
    ----------
    text : str
        The message to display.
    """

    print(colorize(text, Colors.SUCCESS))


def print_failure(text):
    """
    Print a failure message.

    Parameters
    ----------
    text : str
        The message to display.
    """

    print(colorize(text, Colors.FAIL))


# End Helper Functions


if __name__ == "__main__":
    main()
