// ignore_for_file: constant_identifier_names

enum SSHSignal {
  ABRT,
  ALRM,
  FPE,
  HUP,
  ILL,
  INT,
  KILL,
  PIPE,
  QUIT,
  SEGV,
  TERM,
  USR1,
  USR2,
}

extension SSHSignalX on SSHSignal {
  String get name {
    switch (this) {
      case SSHSignal.ABRT:
        return 'ABRT';
      case SSHSignal.ALRM:
        return 'ALRM';
      case SSHSignal.FPE:
        return 'FPE';
      case SSHSignal.HUP:
        return 'HUP';
      case SSHSignal.ILL:
        return 'ILL';
      case SSHSignal.INT:
        return 'INT';
      case SSHSignal.KILL:
        return 'KILL';
      case SSHSignal.PIPE:
        return 'PIPE';
      case SSHSignal.QUIT:
        return 'QUIT';
      case SSHSignal.SEGV:
        return 'SEGV';
      case SSHSignal.TERM:
        return 'TERM';
      case SSHSignal.USR1:
        return 'USR1';
      case SSHSignal.USR2:
        return 'USR2';
    }
  }

  static SSHSignal fromName(String name) {
    switch (name) {
      case 'ABRT':
        return SSHSignal.ABRT;
      case 'ALRM':
        return SSHSignal.ALRM;
      case 'FPE':
        return SSHSignal.FPE;
      case 'HUP':
        return SSHSignal.HUP;
      case 'ILL':
        return SSHSignal.ILL;
      case 'INT':
        return SSHSignal.INT;
      case 'KILL':
        return SSHSignal.KILL;
      case 'PIPE':
        return SSHSignal.PIPE;
      case 'QUIT':
        return SSHSignal.QUIT;
      case 'SEGV':
        return SSHSignal.SEGV;
      case 'TERM':
        return SSHSignal.TERM;
      case 'USR1':
        return SSHSignal.USR1;
      case 'USR2':
        return SSHSignal.USR2;
    }
    throw ArgumentError('Unknown signal name: $name');
  }
}
