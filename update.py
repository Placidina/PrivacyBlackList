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
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient


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


class SSHDeploy:
    def __init__(
        self,
        username: str,
        server: str,
        key_filename: str = None,
        password: str = None,
        port: int = 22,
        path: str = None,
    ) -> None:
        self.username = username
        self.server = server
        self.password = password
        self.key_filename = key_filename
        self.port = port
        self.path = path

        self._ssh_client = self._create_ssh_client()

    def _create_ssh_client(self):
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())

        client.connect(
            self.server,
            self.port,
            self.username,
            self.password,
            key_filename=self.key_filename,
        )

        return client

    def run(self, src: str, dest: str, recursive: bool = False):
        destination: str = dest
        if self.path is not None:
            destination = f"{self.path}/{dest}"

        with SCPClient(self._ssh_client.get_transport()) as scp:
            scp.put(src, destination, recursive)

        return f"file://{destination}"

    def done(self):
        self._ssh_client.close()


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
        "-m",
        "--minimise",
        dest="minimise",
        default=False,
        action="store_true",
        help="Minimise the hosts file ignoring non-necessary lines (empty lines and comments)",
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


def remove_duplicates_and_whitelisted(
    merged, target: str, whitelist: list = None, output=None
):
    """
    Remove duplicates and hosts that are whitelisted.
    """

    if output is None:
        blacklist = open(
            os.path.join(options["output_path"], options["blacklist"]), "w+b"
        )
    else:
        blacklist = output

    merged.seek(0)

    for line in merged.readlines():
        write = True

        line = line.decode(ENCODING).replace("\t+", " ").rstrip(" .")

        if line.startswith("#") or not line.strip():
            blacklist.write(line.encode(ENCODING))
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
            blacklist.write(normalized.encode(ENCODING))

    merged.close()

    if output is None:
        return blacklist

    return None


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


def create_initial_file(src, blacklist: str = None):
    """
    Initialize the file by merging all host files and adding the blacklist data.
    """

    merged = tempfile.NamedTemporaryFile(delete=False)

    try:
        for source in sort_sources(glob(os.path.join(src, "**"))):
            with open(source, "r", encoding=ENCODING) as f:
                merged.write(f.read().encode(ENCODING))

        if blacklist is not None:
            merged.write(blacklist.encode(ENCODING))

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

    src.close()


def write_header(blacklist, rules):
    """
    Write the header information into the newly-created hosts file.
    """

    blacklist.seek(0)
    content = blacklist.read()
    blacklist.seek(0)

    header = f"""\
# Title: Placidina/PrivacyBlackList
#
# This hosts file is a merged collection of hosts from reputable sources,
# with a dash of crowd sourcing via GitHub
#
# Date: {time.strftime('%d %B %Y %H:%M:%S (%Z)', time.gmtime())}
# Number of unique domains: {rules}
#
# Project home page: https://github.com/Placidina/PrivacyBlackList
# Project releases: https://github.com/Placidina/PrivacyBlackList/releases
# ===============================================================
"""

    blacklist.write(header.encode("UTF-8"))
    blacklist.write(content)


def write_custom_blacklist(log, options, datasource):
    """
    Create a custo blacklist.
    """

    for key in datasource["custom"].keys():
        log.info(f"Updating custom blacklist {key}")
        options["blacklist"] = f"custom-{key}"

        with tempfile.NamedTemporaryFile(delete=False) as file:
            rules = len(datasource["custom"][key])
            content = "\n{}".format("\n".join(datasource["custom"][key]))

            file.write(content.encode(ENCODING))
            blacklist = remove_duplicates_and_whitelisted(file, options, datasource)

            write_header_info(blacklist, rules, options)
            blacklist.close()

            log.success(
                f"Success! The hosts file has been saved in folder {os.path.join(options['output_path'], options['blacklist'])}\nIt contains {rules:,} unique entries."
            )


if __name__ == "__main__":
    log = Logging()
    options = parse_arguments()

    if not os.path.exists(options["output"]):
        os.makedirs(options["output"])

    with open(options["datasource"], "r") as file:
        datasource = yaml.safe_load(file)

    deploy = SSHDeploy(
        datasource["deploy"]["ssh"]["username"],
        datasource["deploy"]["ssh"]["server"],
        datasource["deploy"]["ssh"]["key_filename"],
        path=datasource["deploy"]["dest"],
    )

    for key in datasource["rules"]["custom"].keys():
        log.info(f"Updating {key} custom rule")

        count = 0
        blacklist = os.path.join(BASEDIR_PATH, options["output"], f"custom-{key}")
        file = open(blacklist, "w+b")

        for domain in datasource["rules"]["custom"][key]:
            hostname, rule = create_domain_rule(domain, datasource["target"])
            if rule is not None:
                count += 1
                file.write(rule.encode(ENCODING))

        write_header(file, count)
        file.close()

        remote = deploy.run(blacklist, f"custom-{key}")
        log.success(f"Custom rules {key} ({count:,} domains): {remote}")

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
                file.write(content.encode("UTF-8"))

        blacklist = os.path.join(BASEDIR_PATH, options["output"], key)
        merged = create_initial_file(
            os.path.join(BASEDIR_PATH, "data", key),
            "\n".join(
                list(
                    set(
                        datasource["rules"]["blacklist"]
                        + datasource["rules"]["lists"][key]["blacklist"]
                    )
                )
            ),
        )

        if options["minimise"]:
            file = open(blacklist, "w+b")
            minimised = tempfile.NamedTemporaryFile()

            remove_duplicates_and_whitelisted(
                merged,
                datasource["target"],
                list(
                    set(
                        datasource["rules"]["whitelist"]
                        + datasource["rules"]["lists"][key]["whitelist"]
                    )
                ),
                minimised,
            )

            reduce_file_size(datasource["target"], minimised, file)
        else:
            file = remove_duplicates_and_whitelisted(
                merged,
                datasource["target"],
                list(
                    set(
                        datasource["rules"]["whitelist"]
                        + datasource["rules"]["lists"][key]["whitelist"]
                    )
                ),
            )

        file.seek(0)

        lines = set(file.readlines())
        count = len(lines)

        file.writelines(lines)
        write_header(file, count)

        file.close()

        remote = deploy.run(blacklist, key)
        log.success(f"Rule {key.title()} ({count:,} domains): {remote}")

    deploy.done()
