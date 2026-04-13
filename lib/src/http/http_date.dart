/// Tolerant HTTP-date parsing per RFC 7231 §7.1.1.1.
///
/// Supports these forms:
/// - IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
/// - RFC 850:     Sunday, 06-Nov-94 08:49:37 GMT
/// - asctime():   Sun Nov  6 08:49:37 1994
///
/// Returns a UTC [DateTime] or null if parsing fails.
DateTime? parseHttpDate(String input) {
  final s = input.trim();

  final iso8601 = DateTime.tryParse(s);
  if (iso8601 != null) {
    return iso8601.toUtc();
  }

  // Month map (lowercase)
  const months = {
    'jan': 1,
    'feb': 2,
    'mar': 3,
    'apr': 4,
    'may': 5,
    'jun': 6,
    'jul': 7,
    'aug': 8,
    'sep': 9,
    'oct': 10,
    'nov': 11,
    'dec': 12,
  };

  int? monthFromToken(String token) => months[token.toLowerCase()];

  // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
  final rImf = RegExp(
      r"^[A-Za-z]{3},\s+(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+([A-Za-z0-9:+-]+)$");
  final mImf = rImf.firstMatch(s);
  if (mImf != null) {
    final day = int.parse(mImf.group(1)!);
    final mon = monthFromToken(mImf.group(2)!);
    final year = int.parse(mImf.group(3)!);
    final hh = int.parse(mImf.group(4)!);
    final mm = int.parse(mImf.group(5)!);
    final ss = int.parse(mImf.group(6)!);
    if (mon == null) return null;
    // Zone token (mImf.group(7)) is typically GMT; treat any value as UTC.
    return DateTime.utc(year, mon, day, hh, mm, ss);
  }

  // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
  final r850 = RegExp(
      r"^[A-Za-z]+,\s+(\d{1,2})-([A-Za-z]{3})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+([A-Za-z0-9:+-]+)$");
  final m850 = r850.firstMatch(s);
  if (m850 != null) {
    final day = int.parse(m850.group(1)!);
    final mon = monthFromToken(m850.group(2)!);
    final yy = int.parse(m850.group(3)!);
    final year = yy >= 70 ? (1900 + yy) : (2000 + yy);
    final hh = int.parse(m850.group(4)!);
    final mm = int.parse(m850.group(5)!);
    final ss = int.parse(m850.group(6)!);
    if (mon == null) return null;
    return DateTime.utc(year, mon, day, hh, mm, ss);
  }

  // asctime(): Sun Nov  6 08:49:37 1994
  final rAsc = RegExp(
      r"^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$");
  final mAsc = rAsc.firstMatch(s);
  if (mAsc != null) {
    final mon = monthFromToken(mAsc.group(1)!);
    final day = int.parse(mAsc.group(2)!);
    final hh = int.parse(mAsc.group(3)!);
    final mm = int.parse(mAsc.group(4)!);
    final ss = int.parse(mAsc.group(5)!);
    final year = int.parse(mAsc.group(6)!);
    if (mon == null) return null;
    return DateTime.utc(year, mon, day, hh, mm, ss);
  }

  return null;
}
