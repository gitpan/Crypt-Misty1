use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME' => 'Crypt::Misty1',
    'VERSION_FROM' => 'Misty1.pm',
    'PREREQ_PM' => {},
    'AUTHOR' => 'Julius C. Duque',
    'LIBS' => [''],
    'DEFINE' => '',
    'INC' => '-I.',
    'dist' => {'COMPRESS' => 'gzip -9f', 'SUFFIX' => 'gz'},
 # Un-comment this if you add C files to link with later:
    # 'OBJECT'  => '$(O_FILES)', # link all the C files too
);

