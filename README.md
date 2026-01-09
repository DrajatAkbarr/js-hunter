# JS-HUNTER

![Language](https://img.shields.io/badge/Language-Go_1.25%2B-00ADD8?style=flat-square) ![Architecture](https://img.shields.io/badge/Architecture-SAST-orange?style=flat-square) ![Build](https://img.shields.io/badge/Build-Passing-green?style=flat-square) ![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## Overview

**JS-Hunter** is a high-performance, concurrent static analysis tool (SAST) written in Golang. Designed for security researchers and red team operations, it specializes in detecting hardcoded secrets, PII leaks, and vulnerable code patterns within client-side JavaScript files.

Unlike standard regex-based scanners, this tool implements a **Shannon Entropy Analysis Engine** to mathematically validate the randomness of potential secrets, effectively distinguishing between true API keys and false positive placeholders.

## Key Capabilities

* **Smart Entropy Engine (V1.5)** Implements calculus-based entropy analysis to filter out low-quality matches. Only strings with high randomness (like AWS keys or private tokens) are flagged, significantly reducing alert fatigue.

* **Advanced Noise Filtering** Features an internal whitelisting logic that automatically ignores common non-sensitive JavaScript functions (e.g., `setTimeout`, `setInterval`, `jQuery` selectors) to keep reports clean and actionable.

* **Deep Infrastructure Crawling** Automatically parses HTML targets to extract and resolve both absolute and relative JavaScript paths, ensuring comprehensive coverage of the target's client-side assets.

* **Paranoid Scanning Mode** Capable of identifying a wide range of security issues beyond just API keys, including:
    * **DOM XSS Sinks:** Usage of dangerous functions like `eval()` or `innerHTML`.
    * **PII Leaks:** Hardcoded email addresses and internal IP ranges.
    * **Cloud Configs:** Exposed S3 buckets and cloud service credentials.

* **High-Concurrency Architecture** Built using Go's worker pools to perform parallel downloading and scanning of hundreds of files in seconds without blocking resources.

## Installation

Ensure you have **Go 1.25+** installed.

```bash
git clone [https://github.com/DrajatAkbarr/js-hunter.git](https://github.com/DrajatAkbarr/js-hunter.git)
cd js-hunter
go mod tidy
