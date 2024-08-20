# PrivacyBlackList

**PrivacyBlackList** is a custom blacklist that collects and organizes malicious domains that threaten privacy, include adult content, intrusive ads, telemetry, and more. These lists are created to be used with [Pi-hole](https://pi-hole.net/), a network-wide ad blocker that acts as a DNS sinkhole.

The goal of this project is to help protect your network from unwanted content and tracking, providing a safer and cleaner browsing experience.

## Features

- Automatic collection of malicious domains from various reliable sources.
- Regularly updated lists to ensure protection against the latest threats.
- Support for different blocking categories, including privacy, ads, telemetry, and adult content.
- Easy integration with Pi-hole.

## Requirements

- A device with Pi-hole installed (e.g., Raspberry Pi or a Linux server).
- Internet access to perform the crawling and update the blocklists.

## Available Lists

1. ADBlock: https://placidina.github.io/PrivacyBlackList/lists/adblock
2. Privacy: https://placidina.github.io/PrivacyBlackList/lists/privacy
3. Gambling: https://placidina.github.io/PrivacyBlackList/lists/gambling
4. Social: https://placidina.github.io/PrivacyBlackList/lists/social
5. Adult: https://placidina.github.io/PrivacyBlackList/lists/adult

## Usage

The lists created by this project can be added directly to Pi-hole through the web interface or the command line. Ensure that Pi-hole is configured to update the lists periodically.
