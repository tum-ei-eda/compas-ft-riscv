#!/usr/bin/python3

import argparse
import toml


def sihft2str(src_table, sihft):
  ret = ''

  sihft_funcs = [
      f for f in src_table['funcs'] if sihft in src_table['funcs'][f]
  ]
  if len(sihft_funcs):
    ret = "-" + sihft + "="
    for f in sihft_funcs:
      ret = ret + f + ","
    ret = ret[:-1] + " "
  return ret


cli = argparse.ArgumentParser()
cli.add_argument("config_file", help="input config file in TOML format")
args = cli.parse_args()

parsed_data = toml.load(args.config_file)

gcc_target = parsed_data['gcc'].split('-')[0]
clang = parsed_data[
    'clang'] + " -emit-llvm -S --target=" + gcc_target + " -march=" + parsed_data[
        'march'] + " -mabi=" + parsed_data['mabi'] + " " + parsed_data[
            'opt'] + " -isystem " + parsed_data['clib'] + " "
llc = parsed_data['llc'] + " " + parsed_data[
    'opt'] + " -march=" + gcc_target + " -mattr=" + parsed_data['mattr'] + " "
gcc = parsed_data['gcc'] + " -march=" + parsed_data[
    'march'] + " -mabi=" + parsed_data['mabi'] + parsed_data['pre_gcc'] + " "

with open("compile.sh", 'w') as outf:
  gcc_src = ""
  for s in parsed_data['sources']:
    src_name = s['name'].split('.')[0]

    outf.write(clang + parsed_data['prj_root'] + s['path'] + s['name'] +
               " -o " + src_name + ".ll\n")
    outf.write(llc + sihft2str(s, 'NZDC') + sihft2str(s, 'RASM') +
               sihft2str(s, 'CFCSS') + sihft2str(s, 'FGS') + src_name +
               ".ll -o " + src_name + "_sihft.s\n")
    outf.write("\n")
    gcc_src = gcc_src + src_name + "_sihft.s" + " "

  outf.write(gcc + gcc_src + "-o " + parsed_data['prj_name'] + "_sihft.elf" +
             parsed_data['post_gcc'])
