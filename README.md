This repository contains the necessary Python code, TTP templates and Jinja2 templates to convert a Fortinet Firewall configuration file to a Juniper SRX configuration file.

There are a lot of caveats around supported features, the python code has comments that capture the caveats per configuration section.

The only testing done so far on this code is to ensure that the resulting Juniper SRX configuration file is syntatically correct. 
This was done by running it through Batfish (https://github.com/batfish/batfish).

If you fork and improve the code and/or templates, I would appreciate it if you created an issue and put a pointer to your fork and what changes you made in it.
Time permitting (and if it makes sense for my initial use-case) I will integrate those changes.
