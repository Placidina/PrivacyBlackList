#!/usr/bin/env python

import yaml
import argparse
import ipaddress
import os
import re
import sys
import tempfile
import time
import requests

from glob import glob


# Detecting Python 3 for version-dependent implementations
PY3 = sys.version_info >= (3, 0)


if not PY3:
    raise Exception("We do not support Python 2 anymore.")


ENCODING = "UTF-8"
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))


class Logging:
    class COLORS:
        PROMPT = "\033[94m"
        SUCCESS = "\033[92m"
        FAIL = "\033[91m"
        ENDC = "\033[0m"

    def _system_support_color(self):
        """
        Check whether the running terminal or command prompt supports color.
        """

        sys_platform = sys.platform
        supported = sys_platform != "Pocket PC" and (
            sys_platform != "win32" or "ANSICON" in os.environ
        )
        atty_connected = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        return supported and atty_connected

    def _colorize(self, text, color):
        """
        Wrap a string so that it displays in a particular color.
        """

        if not self._system_support_color():
            return text

        return color + text + self.COLORS.ENDC

    def success(self, message):
        """
        Print a success message.
        """

        print(self._colorize(message, self.COLORS.SUCCESS))

    def fail(self, message):
        """
        Print a failure message.
        """

        print(self._colorize(message, self.COLORS.FAIL))

    def info(self, message):
        """
        Print a information message.
        """

        print(self._colorize(message, self.COLORS.PROMPT))


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="Creates a hosts file from hosts stored in the data subfolders"
    )

    parser.add_argument(
        "-d",
        "--datasource",
        dest="datasource",
        default="datasource.yaml",
        help="The datasource collection to create blacklist",
    )
    parser.add_argument(
        "--target-ip", dest="target_ip", default="0.0.0.0", help="Target IP address"
    )
    parser.add_argument(
        "-m",
        "--minimise",
        dest="minimise",
        default=False,
        action="store_true",
        help="Minimise the hosts file ignoring non-necessary lines (empty lines and comments)",
    )

    blacklist_group = parser.add_mutually_exclusive_group(required=True)
    blacklist_group.add_argument(
        "--gambling",
        dest="gambling",
        action="store_true",
        default=False,
        help="Create a list to exclude domains related to gambling",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default="lists",
        help="Output for generated hosts file",
    )

    return vars(parser.parse_args())


def domain_to_idna(line):
    """
    Encode a domain present in a line using IDNA encoding to avoid most encoding issues.
    """

    if not line.startswith("#"):
        separator = re.search(r"[\t\s]", line)
        if separator:
            separator = separator.group()
            parts = line.split(separator)
            for i, part in enumerate(parts):
                if "#" in part:
                    part, comment = part.split("#", 1)
                    parts[i] = (
                        f"{part.encode('idna').decode(ENCODING)}#{comment.strip()}"
                    )
                else:
                    parts[i] = part.encode("idna").decode(ENCODING)
            return separator.join(parts)
        else:
            return line.encode("idna").decode(ENCODING)

    return line


def download(url, params=None, **kwargs):
    """
    Retrieve the contents of the hosts file at the URL, then pass it through domain_to_idna().
    :param url: The URL of the hosts file.
    :param params: Optional parameters to send in the GET request.
    :param kwargs: Additional keyword arguments to pass to requests.get().
    :return: Contents of the hosts file with domain names converted to IDNA encoding.
    """

    try:
        req = requests.get(url=url, params=params, **kwargs)
        req.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving data from {url}: {e}")
        return None

    req.encoding = req.apparent_encoding
    return "\n".join([domain_to_idna(line) for line in req.text.split("\n")])


def remove_duplicates_and_whitelisted(merged_file, options, datasource, output=None):
    """
    Remove duplicates and hosts that are whitelisted.
    """

    if output is None:
        blacklist = open(
            os.path.join(options["output_path"], options["blacklist"]), "w+b"
        )
    else:
        blacklist = output

    rules = 0
    merged_file.seek(0)
    whitelist = datasource[options["blacklist"]]["whitelist"]

    for line in merged_file.readlines():
        write = True

        line = line.decode(ENCODING).replace("\t+", " ").rstrip(" .")

        if line.startswith("#") or not line.strip():
            blacklist.write(line.encode(ENCODING))
            continue

        if "::1" in line:
            continue

        if "@" in line:
            continue

        hostname, normalized_rule = normalize_rule(line, options)

        for match in whitelist:
            if re.search(r"(^|[\s\.])" + re.escape(match) + r"\s", line):
                write = False
                break

        if normalized_rule and write:
            blacklist.write(normalized_rule.encode(ENCODING))
            rules += 1

    merged_file.close()

    if output is None:
        return rules, blacklist

    return rules


def normalize_rule(rule, options):
    """
    Standardize and format the rule string provided.
    """

    def normalize_response(extracted_hostname, extracted_suffix):
        """
        Normalizes the responses after the provision of the extracted hostname and suffix - if exist.
        """

        normalized_rule = f"{options['target_ip']} {extracted_hostname}"
        if extracted_suffix:
            if not extracted_suffix.strip().startswith("#"):
                normalized_rule += f" # {extracted_suffix}"
            else:
                normalized_rule += f" {extracted_suffix}"
        return extracted_hostname, normalized_rule + "\n"

    def is_ip(dataset):
        """
        Checks whether the given dataset is an IP.
        """

        try:
            _ = ipaddress.ip_address(dataset)
            return True
        except ValueError:
            return False

    def belch_unwanted(unwanted):
        """
        Belches unwanted to screen
        """

        print(f"==> {unwanted} <==")
        return None, None

    static_ip_regex = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    split_rule = rule.split(maxsplit=1)

    if is_ip(split_rule[0]):
        if " " in split_rule[-1] or "\t" in split_rule[-1]:
            try:
                hostname, suffix = split_rule[-1].split(maxsplit=1)
            except ValueError:
                hostname, suffix = split_rule[-1], None
        else:
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
            return belch_unwanted(rule)

        return normalize_response(hostname, suffix)

    if (
        not re.search(static_ip_regex, split_rule[0])
        and ":" not in split_rule[0]
        and ".." not in split_rule[0]
        and "/" not in split_rule[0]
        and "." in split_rule[0]
    ):
        try:
            hostname, suffix = split_rule
        except ValueError:
            hostname, suffix = split_rule[0], None

        hostname = hostname.lower()
        return normalize_response(hostname, suffix)

    return belch_unwanted(rule)


def create_initial_file(src_dir, options, datasource):
    """
    Initialize the file by merging all host files and adding the blacklist data.
    :param src_dir: Directory containing the source host files.
    :param options: Dictionary containing options for the merge process.
    :param datasource: Dictionary containing the data source information.
    :return: NamedTemporaryFile object containing the merged host files.
    """

    merged_file = tempfile.NamedTemporaryFile(delete=False)

    try:
        for source in sort_sources(glob(os.path.join(src_dir, "**"))):
            with open(source, "r", encoding=ENCODING) as f:
                merged_file.write(f.read().encode(ENCODING))

        blacklist_data = "\n".join(datasource[options["blacklist"]]["blacklist"])
        merged_file.write(blacklist_data.encode(ENCODING))

        merged_file.seek(0)
        return merged_file

    except Exception as e:
        print(f"Error while creating initial file: {e}")
        merged_file.close()
        os.unlink(merged_file.name)
        return None


def sort_sources(sources):
    """
    Sorts the sources alphabetically, placing sources with 'placidina' in the name at the beginning.
    """

    result = sorted(
        sources.copy(),
        key=lambda x: x.lower().replace("-", "").replace("_", "").replace(" ", ""),
    )
    placidina_positions = [
        index for index, source in enumerate(result) if "placidina" in source.lower()
    ]

    for index in placidina_positions:
        result.insert(0, result.pop(index))

    return result


def reduce_file_size(options, input_file, output_file):
    """Reduce the file size by removing unnecessary lines (empty lines and comments)."""

    input_file.seek(0)
    output_file.write("\n".encode("UTF-8"))

    lines = []
    for line in input_file.readlines():
        line = line.decode("UTF-8")

        if line.startswith(options["target_ip"]):
            lines.append(line[: line.find("#")].strip() + "\n")

    for line in lines:
        output_file.write(line.encode("UTF-8"))

    input_file.close()


def write_header_info(blacklist_file, rules_count, options):
    """Write the header information into the newly-created hosts file."""

    blacklist_file.seek(0)
    content = blacklist_file.read()
    blacklist_file.seek(0)

    header_info = """\
# Title: Placidina/PrivacyBlackList
# Type: {}
#
# This hosts file is a merged collection of hosts from reputable sources,
# with a dash of crowd sourcing via GitHub
#
# Date: {}
# Number of unique domains: {:,}
#
# Fetch the latest version of this file: https://raw.githubusercontent.com/Placidina/PrivacyBlackList/master/{}/{}
# Project home page: https://github.com/Placidina/PrivacyBlackList
# Project releases: https://github.com/Placidina/PrivacyBlackList/releases
# ===============================================================
""".format(
        options["blacklist"].title(),
        time.strftime("%d %B %Y %H:%M:%S (%Z)", time.gmtime()),
        rules_count,
        options["output"],
        options["blacklist"],
    )

    blacklist_file.write(header_info.encode("UTF-8"))
    blacklist_file.write(content)


if __name__ == "__main__":
    log = Logging()
    options = parse_arguments()

    if not os.path.exists(options["datasource"]):
        log.fail("Error: The datasource file does not exist.")
        sys.exit(1)

    with open(options["datasource"], "r") as file:
        datasource = yaml.safe_load(file)

    if options["gambling"]:
        options["blacklist"] = "gambling"

    source_data_path = os.path.join(BASEDIR_PATH, "data", options["blacklist"])
    if not os.path.exists(source_data_path):
        os.makedirs(source_data_path)

    options["output_path"] = os.path.join(BASEDIR_PATH, options["output"])
    if not os.path.exists(options["output_path"]):
        os.makedirs(options["output_path"])

    for source in datasource[options["blacklist"]]["sources"]:
        log.info(
            "Updating {} from vendor {}".format(options["blacklist"], source["vendor"])
        )
        content = download(source["url"]).replace("\r", "")

        hosts_file_path = os.path.join(source_data_path, source["vendor"].lower())
        with open(hosts_file_path, "wb") as data:
            data.write(content.encode("UTF-8"))

    merged = create_initial_file(source_data_path, options, datasource)

    if options["minimise"]:
        minimised = tempfile.NamedTemporaryFile()
        blacklist = open(
            os.path.join(options["output_path"], options["blacklist"]), "w+b"
        )

        rules = remove_duplicates_and_whitelisted(
            merged, options, datasource, minimised
        )
        reduce_file_size(options, minimised, blacklist)
    else:
        rules, blacklist = remove_duplicates_and_whitelisted(
            merged, options, datasource
        )

    write_header_info(blacklist, rules, options)

    blacklist.close()

    log.success(
        "Success! The hosts file has been saved in folder {}\nIt contains {:,} unique entries.".format(
            os.path.join(options["output_path"], options["blacklist"]), rules
        )
    )
