/*!
 * ipv6-classify — expand, compress and classify IPv6 addresses, and detect the
 * EUI-64 interface identifiers that embed a network card's MAC address.
 * Works in Node (require) and the browser (window.ipv6Classify). No dependencies.
 * MIT licence — https://github.com/examineip/ipv6-classify
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ipv6Classify = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Expand an address to its eight four-digit groups.
   * Returns an array of eight lowercase strings, or null if the address is not
   * a valid IPv6 address. Handles "::" and an embedded IPv4 tail.
   */
  function expand(addr) {
    var a = String(addr).trim().toLowerCase();
    if (a.indexOf(':') === -1) { return null; }

    /* a zone index ("%eth0") identifies an interface, not the address */
    var pct = a.indexOf('%');
    if (pct !== -1) { a = a.slice(0, pct); }

    /* an embedded IPv4 tail, as in ::ffff:1.2.3.4 */
    var v4 = a.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (v4) {
      for (var o = 1; o <= 4; o++) {
        if (!/^\d{1,3}$/.test(v4[o])) { return null; }
        if (Number(v4[o]) > 255) { return null; }
      }
      var hi = ((Number(v4[1]) << 8) + Number(v4[2])).toString(16);
      var lo = ((Number(v4[3]) << 8) + Number(v4[4])).toString(16);
      a = a.slice(0, a.length - v4[0].length) + hi + ':' + lo;
    }

    var halves = a.split('::');
    if (halves.length > 2) { return null; }
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];

    if (halves.length === 1) {
      if (head.length !== 8) { return null; }
    }

    var fill = 8 - head.length - tail.length;
    if (fill < 0) { return null; }
    /* "::" must stand for at least one group, or it is just a stray colon */
    if (halves.length === 2 && fill < 1) { return null; }

    var groups = head.slice();
    for (var i = 0; i < fill; i++) { groups.push('0'); }
    groups = groups.concat(tail);
    if (groups.length !== 8) { return null; }

    var out = [];
    for (var j = 0; j < 8; j++) {
      var g = groups[j];
      if (!/^[0-9a-f]{1,4}$/.test(g)) { return null; }
      while (g.length < 4) { g = '0' + g; }
      out.push(g);
    }
    return out;
  }

  /**
   * The canonical compressed form (RFC 5952): lowercase, no leading zeros, and
   * "::" replacing the LONGEST run of zero groups — the leftmost if two runs
   * tie. A run of one group is never compressed.
   */
  function compress(addr) {
    var g = Array.isArray(addr) ? addr.slice() : expand(addr);
    if (!g) { return null; }

    var short = g.map(function (x) { return x.replace(/^0+(?=.)/, ''); });

    var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (var i = 0; i < 8; i++) {
      if (short[i] === '0') {
        if (curStart === -1) { curStart = i; curLen = 0; }
        curLen++;
        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      } else {
        curStart = -1; curLen = 0;
      }
    }

    if (bestLen < 2) { return short.join(':'); }
    var before = short.slice(0, bestStart).join(':');
    var after = short.slice(bestStart + bestLen).join(':');
    return before + '::' + after;
  }

  /**
   * What kind of address this is, and what that means in practice.
   * Returns { type, note }. `type` is 'unparseable' for anything invalid.
   */
  function classify(addr) {
    var g = expand(addr);
    if (!g) { return { type: 'unparseable', note: '' }; }

    var joined = g.join('');
    if (/^0{32}$/.test(joined)) {
      return { type: 'unspecified', note: 'the all-zero address, not a destination' };
    }
    if (/^0{31}1$/.test(joined)) {
      return { type: 'loopback', note: 'never leaves this machine' };
    }

    var first = g[0];

    /* IPv4-mapped, as in ::ffff:1.2.3.4 — an IPv4 address carried in a v6 field */
    if (/^0{20}ffff/.test(joined)) {
      return { type: 'IPv4-mapped', note: 'an IPv4 address in IPv6 form, not native IPv6' };
    }

    if (first.slice(0, 3) === 'fe8') {
      return { type: 'link-local', note: 'never leaves your local network' };
    }
    if (first.slice(0, 2) === 'fc' || first.slice(0, 2) === 'fd') {
      return { type: 'unique local', note: 'private range, cannot reach the internet' };
    }
    if (first.slice(0, 2) === 'ff') {
      return { type: 'multicast', note: '' };
    }
    if (first === '2002') {
      return {
        type: '6to4 tunnel',
        note: 'tunnelled over IPv4, not native - usually slower than plain IPv4'
      };
    }
    if (first === '2001') {
      if (g[1] === '0000') {
        return { type: 'Teredo tunnel', note: 'tunnelled over IPv4, largely abandoned' };
      }
      if (g[1] === '0db8') {
        return { type: 'documentation', note: 'a reserved example range, not a real address' };
      }
    }

    var lead = parseInt(first.charAt(0), 16);
    if (lead >= 2) {
      if (lead <= 3) {
        return { type: 'global unicast', note: 'a real, internet-routable address' };
      }
    }
    return { type: 'other', note: '' };
  }

  /**
   * True when the interface identifier was derived from a MAC address.
   *
   * EUI-64 takes the six-byte MAC, splits it in half and inserts ff:fe in the
   * middle, so the second half of the address becomes a permanent hardware
   * serial that follows the device between networks. Privacy extensions
   * (RFC 4941) replaced this with rotating random identifiers, but plenty of
   * older kit, and a lot of embedded hardware, still does it.
   */
  function isEui64(addr) {
    var g = expand(addr);
    if (!g) { return false; }
    if (g[5].slice(2) !== 'ff') { return false; }
    if (g[6].slice(0, 2) !== 'fe') { return false; }
    return true;
  }

  /**
   * Recover the MAC address an EUI-64 identifier was built from, or null.
   *
   * The transform flips bit 1 of the first byte (the universal/local bit) on
   * the way in, so it is flipped back here. This is what makes EUI-64 a
   * privacy problem rather than a curiosity: the hardware address is not
   * hashed or truncated, it is simply sitting there in the address.
   */
  function macFromEui64(addr) {
    if (!isEui64(addr)) { return null; }
    var g = expand(addr);
    var b = [];
    for (var i = 4; i < 8; i++) {
      b.push(parseInt(g[i].slice(0, 2), 16));
      b.push(parseInt(g[i].slice(2), 16));
    }
    /* b = [b0,b1,b2, ff, fe, b5,b6,b7] */
    var mac = [b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]];
    return mac.map(function (x) {
      var s = x.toString(16);
      return s.length < 2 ? '0' + s : s;
    }).join(':');
  }

  /** True when the address is a real, internet-routable global unicast address. */
  function isGlobal(addr) {
    return classify(addr).type === 'global unicast';
  }

  return {
    expand: expand,
    compress: compress,
    classify: classify,
    isEui64: isEui64,
    macFromEui64: macFromEui64,
    isGlobal: isGlobal
  };
});
