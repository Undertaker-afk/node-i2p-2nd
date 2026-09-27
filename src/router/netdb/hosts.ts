import { createHash } from 'node:crypto';
import { b32AddressFromHash, decodeI2pBase64, encodeI2pBase64, parseB32Hostname } from '../util/encoding.ts';

/**
 * Well-known jump / address-book destinations shipped with Java I2P's hosts.txt.
 * These are the seeds used to pull larger registries (notbob, identiguy, stats, …).
 */
export const BOOTSTRAP_HOSTS: Record<string, string> = {
  'i2p-projekt.i2p': '8ZAW~KzGFMUEj0pdchy6GQOOZbuzbqpWtiApEj8LHy2~O~58XKxRrA43cA23a9oDpNZDqWhRWEtehSnX5NoCwJcXWWdO1ksKEUim6cQLP-VpQyuZTIIqwSADwgoe6ikxZG0NGvy5FijgxF4EW9zg39nhUNKRejYNHhOBZKIX38qYyXoB8XCVJybKg89aMMPsCT884F0CLBKbHeYhpYGmhE4YW~aV21c5pebivvxeJPWuTBAOmYxAIgJE3fFU-fucQn9YyGUFa8F3t-0Vco-9qVNSEWfgrdXOdKT6orr3sfssiKo3ybRWdTpxycZ6wB4qHWgTSU5A-gOA3ACTCMZBsASN3W5cz6GRZCspQ0HNu~R~nJ8V06Mmw~iVYOu5lDvipmG6-dJky6XRxCedczxMM1GWFoieQ8Ysfuxq-j8keEtaYmyUQme6TcviCEvQsxyVirr~dTC-F8aZ~y2AlG5IJz5KD02nO6TRkI2fgjHhv9OZ9nskh-I2jxAzFP6Is1kyAAAA',
  'identiguy.i2p': 'EhDXPsItHi7Dfx8~~0iHPzkjiK1568wqEifARTr-ngIznwVaBmeEnSHXfLkA-7F~Nrqw95yQLlZpja6N1DyQNtJXPx-Db3apXuKwsuTNSGgZme2kFHXPh7PCsfzARwxn4d2-Nx75V4BSCgQr0gRjDa~L~JmtxPRUpZX2NyBvD0w5MSaD~9t4RuCRQ2gVDpUUDcTh2jkm2bX-R9vRIHhCZLasHxDR7rJC9-38uMsQ6ywd4ulQQYIs0kB1sEofdXUypyqphQU9xIxz7azgzKJp~dHnJpJ6SpaH7UrDN-YfOkAvGFBbk9k-u3NGl571Y205dQF~l3XHvVKf6NS9~JvtVh0JibwQ2qLVPy3Y~TtViffvpunNGOrfnVrT5-1c3lWNHx8gTalY3R-vU5rDd8Bz3AhNM6KWktZq8LiHHhJUxIkebXZsid-f2g~QgRRywxG7ksIlKsCMEn076f03L-oWJIlrAg5MdQd-qlg1Bs1IhrR8YT8jNYrX1bGdlmPrJDpiAAAA',
  'stats.i2p': 'Okd5sN9hFWx-sr0HH8EFaxkeIMi6PC5eGTcjM1KB7uQ0ffCUJ2nVKzcsKZFHQc7pLONjOs2LmG5H-2SheVH504EfLZnoB7vxoamhOMENnDABkIRGGoRisc5AcJXQ759LraLRdiGSR0WTHQ0O1TU0hAz7vAv3SOaDp9OwNDr9u902qFzzTKjUTG5vMTayjTkLo2kOwi6NVchDeEj9M7mjj5ySgySbD48QpzBgcqw1R27oIoHQmjgbtbmV2sBL-2Tpyh3lRe1Vip0-K0Sf4D-Zv78MzSh8ibdxNcZACmZiVODpgMj2ejWJHxAEz41RsfBpazPV0d38Mfg4wzaS95R5hHx6eh7oG61KBN1cO1oY8M2oQfISCCpWHPm4WzOlfOHyZOzUHOpcYERAFbsO~w0-ryKIjZJeTzmc314vQB3gG8zMhPRWy9ff6BMkI492DQG2Qv0y3f5fRtx3BfzD7POhujoICzbs8XiCOuuAu8BO0u3k903uHAPNurZx~0jG05TdBQAEAAcAAA==',
  'notbob.i2p': 'gOSToOvSkRewCcwl5mWXbnn1IElEBlGH92vAe0TI8C-Z4tC1DVMNdNlcnUTRcB7znjFTP0vQ42dIDs1dN2Co1kSJ~nXaef4QUS-Ou5kDogPLwJxI1Hj0djktSLKWJSL40FdQvWZ1rwQ7dnaRSyOm8lrgo~HbVlh682CM1JHmEGapQaYiF6zaP4uOpeTFlkk6wEYevQ3Pn4pctJD4XElVLrS2slEsbzim3O5FzFrIVYyskEbnpyMpyffwvsq0R~RF6bhDhQ15rAmJuju91WZ8iUlORQKipougCwBP9DxQ5zdXQWxxhSJ~h604dKhxncetl0skdErLHjwhSI2gl4o66juP9wsjaczBZo4RSil2uWMWApMgvan~9FSRtxriI5f6-X2fTopWa9KlUwMCBTiqYAy9bIdVVhS-xSdFhM~IGPEZ-rlIscdb3Z5Gh1osoO-~SglUcOpj7E-8XjjvsmLkUu9VBxscdD4p3aiyaHGSljkd3WPvlfaOBmqejqEgEWwqBQAEAAEAAA==',
  'inr.i2p': 'GGB99wXYBnX-wOxQ~Xrvo7AvngoYgifvZZL54ksZWzclcirG7AysqfkAKyv906PxfM4y2DcN2K9m4-D99yFj-1BdnUuIEqfi2yuaaVoWuOffT3h9ne~kZnq3C-wrmczD70Gxk4shvSVxMdUEFvEip8QY4K0R-FiKBsFAfWGTE3b9d-QCzP0H9VP5V-CaYjYVQuMRgMluk9gnoLRipvV7483f~rmGgYX8xwygEAQ3v9P4hrAlJrP0lWJLI1K6KQucP3THIxZ4A9Xxnl0I7EZAT8bHwzschFrcDPYM~DtQdkJTz2VphocbNLfIExTrFt88-xC69WE-fSbaMf9jucT4f5kdpfpRu0kM~am40etxPs8uXGF-L9IXCjgUkJHrWdPHeGhnx-ye2xvUTLO2jyga8iY89Ee3IpqivVUg-iAQJzX9NXC29sf0YzNj8d8mdWRNuzbLSx9CVJ3l1NPJr4k7hmCqf8lBGXNIFZQL4Wez1PPcM4gw0o73gqIxkxvVzVcpAAAA',
  'no.i2p': '8jISadUQuR~kZ9YzZxfQwSQRdhY~gkTSgy4l33jKOAraoqSmb~IcoeN5xOXyhtX8gxKEb03-48zPZnso83TwcTFg66~Cu38a59fG0h~vy~WIY5x5CwfkoCFqYmo4OzdnTY-2TcQ2ZN44VA6Sx48UXjEsSdrvn0SfaeMAW5It-N6MAV23Qgc5NgRTVJ6YS74FnRZCy6uGU-RPz1HQQIH~byW-NHBmXAW2Bmv2Kq3bHVHY9tb4d8yfrhlnaf3bfhLeELUbtBnXhLd3Zs2kX6Afz7ofDkpmaygYO6XA8QNIVcM2ub6-jSdsly~EXBtRDzF0WSbT9v8rvpop5TxjwXAnTjbS09Qq8x2Bl8wfkkPz45beN0Je7wrxp0SBk5DHhhvVbbyFUS7bDn1~aTvE7Ujq8ael3myR56jb8NlYiXaiJYgwPXpXx5gSDf8rBaDIdJsSSHWv~DqOfJ1BkhADCEfGZ3QMFY7uWrXGuj0J3OYEvonV-deMoh6pYKtgcFiewJgjAAAA',
  'i2pjump.i2p': 'ouBpQCfwiBcdoZD3vMNT8HXB091kwgI766U6sdWhstY6~7Aixpo8JsNaSO1LV01I20kEzAgmWP8cf5469gSa-YeXAjhKSQPtUgQiKCoRhv2virj--~ecvv4OhyIzCiYoWMMFHV50c02Lg~EE8LGbEkIbRXUZaIWlYwnLC-MzPtuSXhFjHW03h0v~QGeIlYFr8nkpBayqdB8SLkieKygnlOgLRSehmHWZeA0yIz1aCpDuTrZAmAdb3ZwcNm0fxWl~AEpELZ-ax8x6Ibb0kHgPxP1lRr1J7MH~yYXrkymqIPEj-sNLavlAN5oEK6~A45hLd-IENfQ9v-AlntZMon~zeDvxDwHqyKy4OOCbHV7LmitYryEZTVoQNDPPHa6o0pnkBjaPWEnJoDqzU~s-alViTYwR7qkGZMxSp~tej~TngU8GUYEHn4kdTnni0~RTY~50ZyI~2~2ESUCIfFWHzYKQXclzt-uxmNsCL7npmD1-MKZUQ1ECwPR2xKv5vqJwO5ZKAAAA',
};

BOOTSTRAP_HOSTS['i2p-project.i2p'] = BOOTSTRAP_HOSTS['i2p-projekt.i2p']!;

/** Jump services used when a hostname is missing from the local hosts book. */
export const JUMP_HOSTS = ['i2pjump.i2p', 'notbob.i2p'] as const;

/** Default address-book subscription URLs, in fetch order. */
export const ADDRESS_BOOK_SUBSCRIPTIONS = [
  { host: 'i2p-projekt.i2p', path: '/hosts.txt' },
  { host: 'identiguy.i2p', path: '/hosts.txt' },
  { host: 'notbob.i2p', path: '/hosts.txt' },
  { host: 'stats.i2p', path: '/cgi-bin/newhosts.txt' },
  { host: 'inr.i2p', path: '/export/alive-hosts.txt' },
  { host: 'no.i2p', path: '/export/alive-hosts.txt' },
  { host: 'i2pjump.i2p', path: '/hosts' },
] as const;

export class HostsBook {
  private readonly names = new Map<string, Buffer>();

  constructor() {
    for (const [name, dest] of Object.entries(BOOTSTRAP_HOSTS)) this.add(name, dest);
  }

  get size(): number { return this.names.size; }
  namesList(): string[] { return [...this.names.keys()].sort(); }

  add(name: string, destination: string | Buffer): boolean {
    const bytes = readDestinationBytes(destination);
    const key = normalizeHostname(name);
    const existing = this.names.get(key);
    if (existing && existing.equals(bytes)) return false;
    this.names.set(key, Buffer.from(bytes));
    return true;
  }

  get(name: string): Buffer | undefined {
    const bytes = this.names.get(normalizeHostname(name));
    return bytes ? Buffer.from(bytes) : undefined;
  }

  resolve(hostname: string): { destination?: Buffer; hash: Buffer } | undefined {
    const b32 = parseB32Hostname(hostname);
    if (b32) return { hash: b32 };
    const dest = this.get(hostname);
    if (dest) return { destination: dest, hash: createHash('sha256').update(dest).digest() };
    return undefined;
  }

  importHostsTxt(text: string): number {
    let count = 0;
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq < 1) continue;
      try { if (this.add(trimmed.slice(0, eq), trimmed.slice(eq + 1))) count++; }
      catch { /* skip malformed entries */ }
    }
    return count;
  }

  exportHostsTxt(): string {
    return [...this.names.entries()]
      .map(([name, dest]) => `${name}=${encodeI2pBase64(dest)}`)
      .join('\n') + '\n';
  }

  b32Of(name: string): string | undefined {
    const dest = this.get(name);
    if (!dest) return undefined;
    return b32AddressFromHash(createHash('sha256').update(dest).digest());
  }
}

export function normalizeHostname(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

/** Accepts DSA and Ed25519 destinations from published hosts.txt files. */
function readDestinationBytes(value: string | Buffer): Buffer {
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : decodeI2pBase64(value, undefined, 'destination');
  if (bytes.length < 387) throw new Error('Destination is truncated');
  const certificateLength = bytes.readUInt16BE(385);
  if (certificateLength > 16_384 || bytes.length !== 387 + certificateLength) throw new Error('Destination length does not match its certificate');
  return bytes;
}
