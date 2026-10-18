// Windows child.kill() forcibly terminates Node rather than delivering POSIX
// signals. Relay a signal into the actual CLI process for portable handler tests.
process.on('message', message => {
  if (message === 'SIGINT' || message === 'SIGTERM') {
    process.emit(message);
    process.disconnect();
  }
});
