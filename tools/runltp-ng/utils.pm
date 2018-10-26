#!/usr/bin/env perl
#
# Linux Test Project test runner
#
# Copyright (c) 2017-2018 Cyril Hrubis <chrubis@suse.cz>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package utils;

use strict;
use warnings;

use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use log;
use backend;

sub format_memsize
{
	my ($size) = @_;

	if ($size >= 1024 * 1024) {
		return sprintf("%.2f GB ($size KB)", $size/(1024 * 1024));
	}

	if ($size >= 1024) {
		return sprintf("%.2f MB ($size KB)", $size/1024);
	}

	return "$size KB";
}

sub print_sysinfo
{
	my ($sysinfo) = @_;

	print("\nSystem information\n------------------\n\n");

	for (sort(keys %$sysinfo)) {
		printf("%-30s: $sysinfo->{$_}\n", ($_));
	}

	print("\n");
}

sub list_testgroups
{
	my ($self) = @_;

	if (backend::run_cmd($self, "[ -e /opt/ltp/ ]")) {
		print("openposix\n");
	}

	my ($ret, @log) = backend::run_cmd($self, "ls /opt/ltp/runtest/");

	print ("$_\n") for (@log);
}

sub collect_sysinfo
{
	my ($self) = @_;
	my %info;
	my @log;

	if (backend::check_cmd($self, 'uname')) {
		@log = backend::run_cmd($self, 'printf uname-m; uname -m');
		for (@log) {
			if (m/uname-m(.*)/) {
				$info{'arch'} = $1;
			}
		}
		@log = backend::run_cmd($self, 'printf uname-p; uname -p');
		for (@log) {
			if (m/uname-p(.*)/) {
				$info{'cpu'} = $1;
			}
		}
		@log = backend::run_cmd($self, 'printf uname-r; uname -r');
		for (@log) {
			if (m/uname-r(.*)/) {
				$info{'kernel'} = $1;
			}
		}
	}

	@log = backend::run_cmd($self, 'cat /proc/meminfo');
	for (@log) {
		if (m/SwapTotal:\s+(\d+)\s+kB/) {
			$info{'swap'} = format_memsize($1);
		}

		if (m/MemTotal:\s+(\d+)\s+kB/) {
			$info{'RAM'} = format_memsize($1);
		}
	}

	@log = backend::run_cmd($self, 'cat /etc/os-release');
	for (@log) {
		if (m/^ID=\"?([^\"\n]*)\"?/) {
			$info{'distribution'} = $1;
		}
		if (m/^VERSION_ID=\"?([^\"\n]*)\"?/) {
			$info{'distribution_version'} = $1;
		}
	}

	return \%info;
}

sub install_git_cmds
{
	my ($self, $revision) = @_;
	my @cmds;

	push(@cmds, "git clone https://github.com/linux-test-project/ltp.git");
	push(@cmds, "git checkout $revision") if ($revision);

	return @cmds;
}

sub install_zip_cmds
{
	my ($self, $revision) = @_;
	my @cmds;

	$revision //= 'HEAD';

	push(@cmds, "wget http://github.com/linux-test-project/ltp/archive/$revision.zip -O ltp.zip");
	push(@cmds, "unzip ltp.zip");
	push(@cmds, "mv ltp-* ltp");

	return @cmds;
}

sub install_ltp
{
	my ($self, $revision) = @_;
	my $ret;

	my @cmds = ();

	push(@cmds, 'if [ -e /opt/ltp ]; then rm -rf /opt/ltp; fi');
	push(@cmds, 'cd; if [ -e ltp/ ]; then rm -r ltp/; fi');

	if (check_cmd_retry($self, 'git')) {
		push(@cmds, install_git_cmds($self, $revision));
	} else {
		push(@cmds, install_zip_cmds($self, $revision));
	}

	push(@cmds, 'cd ltp');
	push(@cmds, 'make autotools');
	push(@cmds, './configure');
	push(@cmds, 'make -j$(getconf _NPROCESSORS_ONLN)');
	push(@cmds, 'make install');

	my @results;
	if (run_cmds_retry($self, \@cmds, results => \@results) != 0){
		my $last = $results[$#results];
		printf("Failed command: %s\n  output:\n%s\n",
			$last->{cmd}, join("\n  ", @{$last->{log}}));
		return $last->{ret};
	}

	return 0;
}

sub parse_retval
{
	my ($result, $stat, $ret) = @_;

	# Kernel crashed, machine stopped responding
	if (!defined($ret)) {
		$result->{'broken'}++;
		$stat->{'broken'}++;
	}

	if ($ret == 0) {
		$result->{'passed'}++;
		$stat->{'passed'}++;
		return;
	}

	# Command-not-found
	if ($ret == 127) {
		$result->{'broken'}++;
		$stat->{'broken'}++;
		return;
	}

	if ($ret & 1) {
		$result->{'failed'}++;
		$stat->{'failed'}++;
	}

	if ($ret & 2) {
		$result->{'broken'}++;
		$stat->{'broken'}++;
	}

	if ($ret & 4) {
		$result->{'warnings'}++;
		$stat->{'warnings'}++;
	}

	if ($ret & 32) {
		$result->{'skipped'}++;
		$stat->{'skipped'}++;
	}
}

sub check_tainted
{
	my ($self) = @_;
	my $res;

	my ($ret, @log) = backend::run_cmd($self, "printf tainted-; cat /proc/sys/kernel/tainted");

	return undef if ($ret);

	for (@log) {
		if (m/tainted-(\d+)/) {
			$res = $1;
		}
	}

	return $res;
}

sub setup_ltp_run
{
	my ($self, $runtest) = @_;
	my @tests;

	backend::run_cmd($self, "cd /opt/ltp/");
	@tests = backend::read_file($self, "runtest/$runtest") if defined($runtest);
	backend::run_cmd($self, "cd testcases/bin");
	backend::run_cmd($self, "export PATH=\$PATH:\$PWD");

	return \@tests;
}

sub reboot
{
	my ($self, $reason) = @_;

	print("$reason, attempting to reboot...\n");
	backend::reboot($self);
	setup_ltp_run($self);
}


=head2 run_cmds_retry

    run_cmds_retry($self, <ARRAY of commands>, [timeout => <seconds>, retries => <number>, results => <array_ref>]);

Run commands sequentially. If a command failed in case of timeout, reboot the SUT.
After reboot the sequenz is restarted from the first  command.
The sequence stops on the first commaned which exit with none zero.

The function retrieves a array of hash refs or the exitcode of the last command in scalar context:
  (
	{ cmd=> <the command>, ret => <returnvalue>, log => <array ref of output lines> },
	{ cmd=>'echo "foo"', ret => 0, log => ('foo') }
	...
  )
=cut
sub run_cmds_retry
{
	my ($self, $cmd, %args) = @_;
	my @ret;
	$args{retries} //= 3;

	for my $cnt (1 .. $args{retries}) {
		@ret = backend::run_cmds($self, $cmd, %args);
		last if(defined($ret[$#ret]->{ret}));
		if ($cnt == $args{retries}){
			die ("Unable to recover SUT");
		}
		reboot($self, "Timeout on command: " . $ret[$#ret]->{cmd});
	}
	if ($args{results}){
		push(@{$args{results}} , @ret);
	}
	wantarray ? @ret : $ret[$#ret]->{ret};
}

sub check_cmd_retry
{
	my ($self, $cmd, %args) = @_;
	my $ret = run_cmds_retry($self, [$cmd], %args);
	return $ret != 127;
}

sub run_ltp
{
	my ($self, $runtest, $exclude) = @_;
	my @results;
	my %reshash;

	my %empty_result = (
		'runtime' => 0,
		'runs' => 0,
		'passed' => 0,
		'failed' => 0,
		'broken' => 0,
		'skipped' => 0,
		'warnings' => 0,
	);

	my %stats = (
		'passed' => 0,
		'failed' => 0,
		'broken' => 0,
		'skipped' => 0,
		'warnings' => 0,
	);

	my $tests = setup_ltp_run($self, $runtest);
	my $start_tainted = check_tainted($self);
	my $start_time = clock_gettime(CLOCK_MONOTONIC);

	for (@$tests) {
		next if m/^\s*($|#)/;
		chomp;
		my ($tid, $c) = split(/\s/, $_, 2);
		next if ($exclude && $tid =~ $exclude);
		print("Executing $tid\n");
		my $test_start_time = clock_gettime(CLOCK_MONOTONIC);
		my ($ret, @log) = backend::run_cmd($self, "$c", 600);
		my $test_end_time = clock_gettime(CLOCK_MONOTONIC);

		my $result = {};

		if (defined($reshash{$tid})) {
			$result = $reshash{$tid};
		} else {
			$result = {%empty_result};
			$result->{'tid'} = $tid;
			$result->{'log'} = [];
		}

		push(@{$result->{'log'}}, @log);
		$result->{'runtime'} += $test_end_time - $test_start_time;
		$result->{'runs'} += 1;

		parse_retval($result, \%stats, $ret);

		if (!defined($reshash{$tid})) {
			push(@results, $result);
			$reshash{$tid} = $result;
		}

		if (!defined($ret)) {
			reboot($self, 'Machine stopped respoding');
		} elsif ($ret) {
			my $tainted = check_tainted($self);
			reboot($self, 'Kernel was tained') if ($tainted != $start_tainted);
		}
	}

	my $stop_time = clock_gettime(CLOCK_MONOTONIC);

	$stats{'runtime'} = $stop_time - $start_time;

	return (\%stats, \@results);
}

1;
