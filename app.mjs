#!/usr/local/bin/node

import { Reader } from "@maxmind/geoip2-node";
import * as fs from "fs";
import path from "path";
import * as readline from "readline";
import { fileURLToPath } from "url";
import * as dotenv from "dotenv";
import { Redis } from "ioredis";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ENV_PATH = path.join(__dirname, '.env');
dotenv.config({ path: ENV_PATH });

const IPCIDR = (await import("ip-cidr")).default;

const AsnDbBuffer = fs.readFileSync(__dirname + "/maxmind/GeoLite2-ASN.mmdb");
const AsnReader = Reader.openBuffer(AsnDbBuffer);

const CountryDbBuffer = fs.readFileSync(__dirname + "/maxmind/GeoLite2-Country.mmdb");
const CountryReader = Reader.openBuffer(CountryDbBuffer);

const redis = new Redis(process.env.REDIS_URL);

const kindAllowList = {
  0: true,
  2: true,
  3: true,
  5: true,
  // 6: true,
  7: true,
  8: true,
  1984: true,
  9735: true,
  10000: true,
  10001: true,
  10002: true,
  30000: true,
  30001: true,
  30008: true,
  30009: true,
};

const ipAllowList = [
  "127.0.0.0/8",
  "192.168.0.0/16",
  "172.16.0.0/12",
  "10.0.0.0/8",
  "fd00::/8",
];

const pubkeyAllowList = {
  "b707d6be7fd9cc9e1aee83e81c3994156cfcf74ded5b09111930fdeeeb5a0c20": true, //It's me!
};

const AsnAllowList = {
  // 14618: true, // AWS
};

const AsnDenyList = {
  20473: true, // ???
};

const CountryAllowList = {
  "JP": true, // JP only relay
};

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const isPassportHolder = async (pubkey) => {
  const key = `passport-${pubkey}`;
  const current = new Date();
  let value = 0;
  try {
    value = await redis.get(key);
  } catch (err) {
    console.error(err);
    return false;
  }
  if (value >= current)
    return true;
};

rl.on("line", async (line) => {
  console.error(line);
  let req = JSON.parse(line);
  let res = {};
  try {
    res = { id: req.event.id }; // must echo the event"s id
  } catch (error) {
    console.error(error);
    return;
  }

  if (process.env.CHAT === "deny" && (req.event.kind === 4 || (40 <= req.event.kind && req.event.kind <= 49))) {
    res.action = "reject";
    res.msg = "blocked: Event not allowed";
    console.log(JSON.stringify(res));
    return;
  }

  if (req.type === "lookback") {
    return;
  }

  if (req.sourceType === "Stream") {
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (req.type !== "new") {
    console.error("unexpected request type"); // will appear in strfry logs
    return;
  }

  if (await isPassportHolder(req.event.pubkey)) {
    console.error("Allow: Passport user");
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (pubkeyAllowList[req.event.pubkey]) {
    console.error("Allow: user");
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (kindAllowList[req.event.kind]) {
    console.error("Allow: kind");
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  let isLocalIp = false;
  ipAllowList.some((value) => {
    if (!IPCIDR.isValidCIDR(value)) {
      return;
    }
    let cidr = new IPCIDR(value);
    if (cidr.contains(req.sourceInfo)) {
      isLocalIp = true;
      return true;
    } else {
      return false;
    }
  });
  if (isLocalIp) {
    console.error("Allow: Local IP");
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (AsnDenyList[AsnReader.asn(req.sourceInfo).autonomousSystemNumber]) {
    res.action = "reject";
    res.msg = `blocked: ASN ${AsnReader.asn(req.sourceInfo).autonomousSystemNumber} not allowed`;
    console.log(JSON.stringify(res));
    return;
  }

  if (AsnAllowList[AsnReader.asn(req.sourceInfo).autonomousSystemNumber]) {
    console.error("Allow: Allowed ASN");
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (!CountryAllowList[CountryReader.country(req.sourceInfo).country.isoCode]) {
    res.action = "reject";
    res.msg = `blocked: Country ${CountryReader.country(req.sourceInfo).country.isoCode} not allowed`;
    console.log(JSON.stringify(res));
    return;
  }

  console.error("Allow: No rule");
  res.action = "accept";
  console.log(JSON.stringify(res));
  return;
});