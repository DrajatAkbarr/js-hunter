<div align="center">

```text
       __ ____       __  ____  __  _  ______  ____  ____ 
      / // __/____  / / / / / / / / /_  __/ / __/ / __ \
 __  / /_\ \/ ___/ / /_/ / / / / /   / /   / _/  / /_/ /
/ /_/ /___/ /     / __  / /_/ / /   / /   / /___/ _, _/ 
\____//____/     /_/ /_/\____/_/   /_/   /_____/_/ |_|  
                                                         
>>> INTELLIGENT CLIENT-SIDE STATIC ANALYSIS TOOL (SAST) <<<
</div>

PROJECT OVERVIEW
JS-HUNTER is an advanced offensive security tool designed for automated reconnaissance and static analysis of JavaScript files. Unlike traditional scanners that rely solely on Regular Expressions (Regex), JS-HUNTER implements a Multi-Layer Analysis Engine combining signature matching with Shannon Entropy Mathematics.

This approach allows the tool to distinguish between "false positive" strings (like placeholders or common functions) and "true positive" secrets (like high-entropy API keys, PII, or hardcoded credentials), significantly reducing noise for security researchers.

Core Capabilities

Deep Crawling: Automatically parses HTML to extract absolute and relative script paths.

Entropy Analysis: Calculus-based validation to detect random strings (potential keys).

Smart Filtering: Internal whitelist engine to ignore common JS noise (setTimeout, node_modules, jquery).

Paranoid Mode: Aggressive scanning for PII (Emails), Internal IPs, and Dangerous Functions (eval, innerHTML).

TECHNICAL ARCHITECTURE
The scanner operates on a 3-stage pipeline designed for high-concurrency and accuracy.
graph TD;
    A[Target URL] -->|Crawler Engine| B(Extract JS Links);
    B -->|Worker Pool (Concurrency)| C{Download Content};
    C -->|Layer 1: Regex| D[Signature Match];
    D -->|Layer 2: Noise Filter| E[Whitelist Check];
    E -->|Layer 3: Math| F[Shannon Entropy Calc];
    F -->|Result| G[JSON Report];

INSTALLATION
Ensure you have Go 1.25+ installed on your machine.

