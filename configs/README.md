# mosdns cfst_pool Integration

This directory contains example configurations for the `cfst_pool` plugin.

## cfst_pool.yaml

Example config demonstrating in-process CloudflareSpeedTest integration with mosdns.

### Quick Start

```bash
# Build mosdns with cfst_pool support
go build -o /tmp/mosdns-cfst

# Create cache directory
sudo mkdir -p /var/lib/mosdns

# Create Cloudflare CIDR file (for ip_set matcher)
sudo mkdir -p /etc/mosdns
sudo tee /etc/mosdns/cloudflare.txt > /dev/null <<EOF
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
EOF

# Run with the example config
/tmp/mosdns-cfst start -c configs/cfst_pool.yaml
```

### Expected Output

You should see logs like:
```
[INFO] cfst_pool: refresh complete ipv4=10 ipv6=0
```

And the cache file will contain:
```bash
cat /var/lib/mosdns/cfst_pool.json
```

### Manual Refresh

Send SIGUSR1 to trigger immediate refresh:
```bash
pkill -USR1 mosdns-cfst
```

## Integration Details

The config demonstrates:
1. **cfst_pool**: Runs CloudflareSpeedTest in-process, exposes FastIPProvider interface
2. **ip_set**: Matches Cloudflare IPs in responses
3. **sequence**: Ties it together — when response IP matches Cloudflare CIDR, prepend fast IPs from cfst_pool
4. **lpush**: Dual-mode executable — `$cfst_pool` references the dynamic provider

### Workflow Transformation

**Before (external cfst):**
```bash
cfst -dn 5 -dt 5 -n 100 -url https://cfst.raenzo.com/test
# Manually copy resulting IPs into mosdns YAML as lpush ${ip1} ${ip2} ...
```

**After (in-process):**
- mosdns loads cfst_pool at startup
- Runs full pipeline internally
- lpull `$cfst_pool` pulls live IPs at query time
- Refreshes hourly + on SIGUSR1

## Production Considerations

This is a minimal example. Production deployments should add:
- DNS listeners (UDP/TCP/DoH/DoT)
- Query cache
- Fallback forwarders
- Access control
- Monitoring/metrics
