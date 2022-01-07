class SftpRequestId {
  static const max = 0xFFFFFFFF;

  var _id = 0;

  int get next {
    return _id++ % max;
  }
}
