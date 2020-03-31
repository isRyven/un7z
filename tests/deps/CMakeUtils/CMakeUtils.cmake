# checks file hash to determine whether file is new (requires cmake rerun)
function(file_was_changed filepath result)
	# get checksum
	file(SHA256 ${filepath} file_checksum_hash)
	# get old checksum if any
	list(FIND _CHECKSUMKEYS_ "${filepath}" cached_checksum_index)
	if ("${cached_checksum_index}" STREQUAL "-1")
		# no entry was found, file is new
		list(APPEND _CHECKSUMKEYS_ "${filepath}")
		list(APPEND _CHECKSUMVALS_ "${file_checksum_hash}")
		set(${result} "1" PARENT_SCOPE)
	else()
		list(GET _CHECKSUMVALS_ "${cached_checksum_index}" cached_checksum_hash)
		if (NOT file_checksum_hash STREQUAL cached_checksum_hash)
			# update hash
			list(INSERT _CHECKSUMVALS_ "${cached_checksum_index}" "${file_checksum_hash}")			
			set(${result} "1" PARENT_SCOPE)
		else()
			set(${result} "0" PARENT_SCOPE)
		endif()
	endif()
	# update cache
	set(_CHECKSUMKEYS_ "${_CHECKSUMKEYS_}" CACHE INTERNAL "checksum keys" FORCE)
	set(_CHECKSUMVALS_ "${_CHECKSUMVALS_}" CACHE INTERNAL "checksum values" FORCE)
endfunction()

# little resource compiler
function(file_generate_rc inpath outpath rcname)
	file(READ "${inpath}" file_bytes HEX)
	# optional null termination
	list(LENGTH ARGN num_extra_args)
	if (${num_extra_args} GREATER 0)
		list(GET ARGN 0 append_null)
		if ("${append_null}" EQUAL 1)
			string(APPEND file_bytes "00")
		endif()
	endif()
	# append hex prefixes
    string(REGEX REPLACE "(..)(..)(..)(..)(..)" "0x\\1,0x\\2,0x\\3,0x\\4,0x\\5," hex_codes "${file_bytes}")
    string(LENGTH "${file_bytes}" n_bytes2)
    math(EXPR file_size "${n_bytes2} / 2")
    math(EXPR remainder "${file_size} % 5")
    set(cleanup_re "$")
    set(cleanup_sub )
    while(remainder)
        set(cleanup_re "(..)${cleanup_re}")
        set(cleanup_sub "0x\\${remainder},${cleanup_sub}")
        math(EXPR remainder "${remainder} - 1")
    endwhile()
    if(NOT cleanup_re STREQUAL "$")
        string(REGEX REPLACE "${cleanup_re}" "${cleanup_sub}" hex_codes "${hex_codes}")
    endif()
    string(CONFIGURE [[
        const unsigned char @rcname@[] = {
            @hex_codes@
        };
        const unsigned int @rcname@_length = @file_size@; 
    ]] code)
    file(WRITE "${outpath}" "${code}")
endfunction()

# generate file resouce if needed
# accepts optional last argument to determine if null 
# should be appended to the buffer
function(file_intern filePath resName resOutPath)
	get_filename_component(fileName "${filePath}" NAME)
	set(outputFile "${CMAKE_CURRENT_BINARY_DIR}/${fileName}.c")
	file_was_changed("${filePath}" wasChanged)
	if ("${wasChanged}" STREQUAL "1")
		if (${ARGN})
			file_generate_rc(${filePath} ${outputFile} ${resName} 1)
		else()
			file_generate_rc(${filePath} ${outputFile} ${resName} 0)
		endif()
	endif()
	set("${resOutPath}" "${outputFile}" PARENT_SCOPE)
endfunction()
