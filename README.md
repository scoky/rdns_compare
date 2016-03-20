# rdns_compare

This tool scans recursive resolvers measuring resolution performance. The tool reports back the timing results for each recursive resolver. To obtain detailed results, use the -c option to write each resolution to a file in csv format.

By default, the tools fetches lists of public resolvers and popular hostnames over HTTPs, but can be configured to use other resolvers and hostnames using the -prai options.

Depending upon the number of hostnames and resolvers tested, the tool can take several minutes to complete. Use the --progress option to see the current status of the tool.

The tool attempts to bind to both IPv4 and IPv6 interfaces. To limit the tool to a specific interface, use the -b option.

See example/ for example output.
