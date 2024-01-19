#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdbool.h>
#include "reporter.h"
#include "log.h"

static FILE *report_fp = NULL;
static struct timeval start_time;
static bool started = false;

void start_report(char* filename) {
  report_fp = fopen(filename, "w");
  if (report_fp == NULL) {
    printf("open file %s failed\n", filename);
    exit(1);
  }
  log(DEBUG, "start report");
  gettimeofday(&start_time, NULL);
  started = true;
}
void report(int val) {
  if (!started) return ;
  struct timeval cur_time;
  gettimeofday(&cur_time, NULL);
  int seconds = cur_time.tv_sec - start_time.tv_sec;
  int useconds = cur_time.tv_usec - start_time.tv_usec;
  double elapsed_time = seconds + 1.0 * useconds / 1000000.0;
  fprintf(report_fp, "%lf %d\n", elapsed_time, val);
  fflush(report_fp);
}
void end_report() {
  if (started)
    fclose(report_fp);
}