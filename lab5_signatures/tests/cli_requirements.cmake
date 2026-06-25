if(NOT DEFINED SIGTOOL OR NOT EXISTS "${SIGTOOL}")
    message(FATAL_ERROR "SIGTOOL must name the built sigtool executable")
endif()

if(NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "WORK_DIR is required")
endif()

file(MAKE_DIRECTORY "${WORK_DIR}")
file(WRITE "${WORK_DIR}/message.bin" "Lab 5 DER key end-to-end test\n")

function(run_ok label)
    execute_process(
        COMMAND "${SIGTOOL}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE stdout
        ERROR_VARIABLE stderr
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR
            "${label} failed with exit code ${result}\nstdout:\n${stdout}\nstderr:\n${stderr}")
    endif()
endfunction()

function(run_fail label)
    execute_process(
        COMMAND "${SIGTOOL}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE stdout
        ERROR_VARIABLE stderr
    )
    if(result EQUAL 0)
        message(FATAL_ERROR
            "${label} unexpectedly succeeded\nstdout:\n${stdout}\nstderr:\n${stderr}")
    endif()
endfunction()

foreach(algorithm IN ITEMS ecdsa-p256 rsa-pss-3072)
    if(algorithm STREQUAL "ecdsa-p256")
        set(prefix ecdsa)
        set(encoding der)
    else()
        set(prefix rsa)
        set(encoding raw)
    endif()

    set(private_key "${WORK_DIR}/${prefix}_private.der")
    set(public_key "${WORK_DIR}/${prefix}_public.der")
    set(signature "${WORK_DIR}/${prefix}.sig")

    run_ok(
        "${algorithm} DER keygen"
        keygen --algo "${algorithm}"
        --priv "${private_key}" --pub "${public_key}" --format der
    )
    run_ok(
        "${algorithm} sign with DER private key"
        sign --algo "${algorithm}" --priv "${private_key}"
        --in "${WORK_DIR}/message.bin" --out "${signature}"
        --hash sha256 --encode "${encoding}"
    )
    run_ok(
        "${algorithm} verify with DER public key"
        verify --algo "${algorithm}" --pub "${public_key}"
        --in "${WORK_DIR}/message.bin" --sig "${signature}"
        --hash sha256 --encode "${encoding}"
    )
endforeach()

run_fail(
    "unsupported signature encoding"
    sign --algo ecdsa-p256 --priv "${WORK_DIR}/ecdsa_private.der"
    --in "${WORK_DIR}/message.bin" --out "${WORK_DIR}/unsupported.sig"
    --hash sha256 --encode hex
)

run_fail(
    "unsupported RSA-PSS parameter"
    sign --algo rsa-pss-3072 --priv "${WORK_DIR}/rsa_private.der"
    --in "${WORK_DIR}/message.bin" --out "${WORK_DIR}/unsupported-parameter.sig"
    --hash sha256 --encode raw --salt-len 20
)

message(STATUS "DER key end-to-end and unsupported option checks passed")
