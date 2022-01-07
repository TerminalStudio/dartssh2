extension StirngX on String {
  int get octal => int.parse(this, radix: 8);
}
