<h1>vulchk - Potential vulnerability Scanner Tool</h1>

<h2>Overview</h2>
<p>
    The <strong>vulchk Scanner Tool</strong> is a Python-based application designed to scan web applications for Potential vulnerabilities and open ports. This tool is intended for educational purposes and should only be used on systems for which you have explicit permission to test.
</p>

<h2>Features</h2>
<ul>
    <li><strong>Port Scanning</strong>: Quickly checks for open ports on the target web application, including common ports such as HTTP (80), HTTPS (443), and others.</li>
    <li><strong>Vulnerability Detection</strong>: Identifies basic security vulnerabilities by checking for the presence of important HTTP security headers, including:
        <ul>
            <li><code>X-Frame-Options</code></li>
            <li><code>X-Content-Type-Options</code></li>
            <li><code>X-XSS-Protection</code></li>
        </ul>
    </li>
    <li><strong>Potential Data Leak Detection</strong>: Scans the response content for potential information disclosures, such as:
        <ul>
            <li>Error messages that may reveal sensitive information</li>
            <li>Keywords like "password" or "secret" that may indicate sensitive data exposure</li>
        </ul>
    </li>
    <li><strong>Multithreaded Scanning</strong>: Utilizes threading to perform scans efficiently, allowing for faster results.</li>
</ul>

<h2>Usage</h2>
<ol>
    <li><strong>Clone the Repository</strong>:
        <pre><code>git clone https://github.com/swasthik-moolya/vulchk.git
cd vulchk</code></pre>
    </li>
    <li><strong>Install Required Packages</strong>: Ensure you have Python installed, then install the required packages:
        <pre><code>pip install requests</code></pre>
    </li>
    <li><strong>Run the Tool</strong>: Execute the script:
        <pre><code>python3 vulchk.sh</code></pre>
    </li>
    <li><strong>Input the Target URL</strong>: When prompted, enter the target URL you wish to scan (ensure you have permission to scan the target).</li>
</ol>

<h2>Important Note</h2>
<p>
    This tool is intended for educational purposes only. Always ensure you have permission to scan any target system. Unauthorized scanning may be illegal and unethical.
</p>

<h2>Contributing</h2>
<p>
    Contributions are welcome! If you have suggestions for improvements or additional features, feel free to open an issue or submit a pull request.
</p>

<h2>License</h2>
<p>
    This project is licensed under the MIT License - see the <a href="LICENSE">LICENSE</a> file for details.
</p>
