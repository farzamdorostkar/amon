#ifndef AMON_LOG_H
#define AMON_LOG_H

enum amon_log_level {ERROR=0, WARNING, INFO, DEBUG};

// Check the log level and category and writes the message to a buffer,
// then writes its content to file descriptor 2 (stderr)
void dw_log(enum amon_log_level level, const char *fmt, ...);

// Writes the message to a buffer and then writes its content to fd
void amon_fprintf(int fd, const char *fmt, ...);

#endif /* AMON_LOG_H */