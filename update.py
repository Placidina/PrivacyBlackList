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
        "-o",
        "--output",
        dest="output",
        default="rules",
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


def remove_duplicates_and_whitelisted(src, dest, target: str, whitelist: list = []):
    """
    Remove duplicates and hosts that are whitelisted.
    """

    src.seek(0)

    for line in src.readlines():
        write = True

        line = line.decode(ENCODING).replace("\t+", " ").rstrip(" .")

        if line.startswith("#") or not line.strip():
            dest.write(line.encode(ENCODING))
            continue

        if "::1" in line:
            continue

        if "@" in line:
            continue

        hostname, normalized = create_domain_rule(line, target)

        for match in whitelist:
            if re.search(r"(^|[\s\.])" + re.escape(match) + r"\s", line):
                write = False
                break

        if normalized and write:
            dest.write(normalized.encode(ENCODING))

    src.close()
    return dest


def create_domain_rule(domain: str, target: str = None):
    """
    Standardize and format the rule string provided.
    """

    def normalize(hostname, suffix):
        """
        Normalizes the responses after the provision of the extracted hostname and suffix - if exist.
        """

        normalized = f"{target} {hostname}"
        if suffix:
            if not suffix.strip().startswith("#"):
                normalized += f" # {suffix}"
            else:
                normalized += f" {suffix}"
        return hostname, normalized + "\n"

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
    rule = domain.split(maxsplit=1)

    if is_ip(rule[0]):
        if " " in rule[-1] or "\t" in rule[-1]:
            try:
                hostname, suffix = rule[-1].split(maxsplit=1)
            except ValueError:
                hostname, suffix = rule[-1], None
        else:
            hostname, suffix = rule[-1], None

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

        return normalize(hostname, suffix)

    if (
        not re.search(static_ip_regex, rule[0])
        and ":" not in rule[0]
        and ".." not in rule[0]
        and "/" not in rule[0]
        and "." in rule[0]
    ):
        try:
            hostname, suffix = rule
        except ValueError:
            hostname, suffix = rule[0], None

        hostname = hostname.lower()
        return normalize(hostname, suffix)

    return belch_unwanted(rule)


def create_initial_file(src, blacklist: list = []):
    """
    Initialize the file by merging all host files and adding the blacklist data.
    """

    merged = tempfile.NamedTemporaryFile(delete=False)

    try:
        for source in sort_sources(glob(os.path.join(src, "**"))):
            with open(source, "r", encoding=ENCODING) as f:
                merged.write(f.read().encode(ENCODING))

        if blacklist is not None:
            merged.write("".join(blacklist).encode(ENCODING))

        merged.seek(0)
        return merged
    except Exception as e:
        print(f"Error while creating initial file: {e}")

        merged.close()
        os.unlink(merged.name)

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


def reduce_file_size(target, src, dest):
    """
    Reduce the file size by removing unnecessary lines (empty lines and comments).
    """

    src.seek(0)
    dest.write("\n".encode("UTF-8"))

    lines = []
    for line in src.readlines():
        line = line.decode("UTF-8")

        if line.startswith(target):
            lines.append(line[: line.find("#")].strip() + "\n")

    for line in lines:
        dest.write(line.encode("UTF-8"))


def write_header(file, relative_path: str, total_unique_domains: int):
    """
    Write the header information into the newly-created hosts file.
    """

    file.seek(0)
    content = file.read()
    file.seek(0)

    header = f"""\
# Title: Placidina/PrivacyBlackList
#
# This hosts file is a merged collection of hosts from reputable sources,
# with a dash of crowd sourcing via GitHub
#
# Date: {time.strftime('%d %B %Y %H:%M:%S (%Z)', time.gmtime())}
# Number of unique domains: {total_unique_domains}
#
# Fetch the latest version of this file: https://placidina.github.io/PrivacyBlackList/{relative_path}
#
# Project home page: https://github.com/Placidina/PrivacyBlackList
# Project releases: https://github.com/Placidina/PrivacyBlackList/releases
# ===============================================================\n
"""

    file.write(header.encode("UTF-8"))
    file.write(content)


if __name__ == "__main__":
    log = Logging()
    options = parse_arguments()

    if not os.path.exists(os.path.join(BASEDIR_PATH, options["output"], "custom")):
        os.makedirs(os.path.join(BASEDIR_PATH, options["output"], "custom"))

    if not os.path.exists(os.path.join(BASEDIR_PATH, options["output"], "lists")):
        os.makedirs(os.path.join(BASEDIR_PATH, options["output"], "lists"))

    with open(options["datasource"], "r") as file:
        datasource = yaml.safe_load(file)

    for key in datasource["rules"]["custom"].keys():
        log.info(f"Updating {key} custom rule")

        rules = []
        with open(
            os.path.join(BASEDIR_PATH, options["output"], "custom", key), "w+b"
        ) as blacklist:
            for domain in datasource["rules"]["custom"][key]:
                hostname, rule = create_domain_rule(domain, datasource["target"])
                if rule is not None:
                    rules.append(rule)

            blacklist.write("".join(rules).encode(ENCODING))
            write_header(blacklist, f"custom/{key}", len(rules))

        log.success(
            f"Custom rules for {key} updated with {len(rules):,} unique domains"
        )

    for key in datasource["rules"]["lists"].keys():
        log.info(f"Updating {key.title()} ...")

        if not os.path.exists(os.path.join(BASEDIR_PATH, "data", key)):
            os.makedirs(os.path.join(BASEDIR_PATH, "data", key))

        for source in datasource["rules"]["lists"][key]["sources"]:
            log.info(f"Updating {source['name'].replace('-', ' ').title()} ...")

            content = download(source["url"])

            with open(
                os.path.join(BASEDIR_PATH, "data", key, source["name"].lower()), "wb"
            ) as file:
                file.write(content.encode(ENCODING))

        blacklist = list(
            set(
                datasource["rules"]["blacklist"]
                + datasource["rules"]["lists"][key]["blacklist"]
            )
        )

        whitelist = list(
            set(
                datasource["rules"]["whitelist"]
                + datasource["rules"]["lists"][key]["whitelist"]
            )
        )

        total_unique_domains = 0
        merged = create_initial_file(os.path.join(BASEDIR_PATH, "data", key), blacklist)

        with tempfile.NamedTemporaryFile(delete=False) as minimised:
            remove_duplicates_and_whitelisted(
                merged, minimised, datasource["target"], whitelist
            )

            with open(
                os.path.join(BASEDIR_PATH, options["output"], "lists", key), "w+b"
            ) as blacklist:
                reduce_file_size(datasource["target"], minimised, blacklist)

                blacklist.seek(0)
                lines = set(blacklist.readlines())
                blacklist.seek(0)

                blacklist.writelines(lines)
                total_unique_domains = len(lines)

                write_header(blacklist, f"lists/{key}", total_unique_domains)

        log.success(
            f"{key.title()} updated with {total_unique_domains:,} unique domains"
        )
