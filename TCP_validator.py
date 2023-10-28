import numpy as np


def generate_pseudo_header(source_ip, dest_ip, tcp_length):
    '''
    This function generates a pseudo header for the tcp data
    using the source ip, destination ip, and tcp length.

    param: source_ip: the source ip address in bytes
    param: dest_ip: the destination ip address in bytes
    param: tcp_length: the length of the tcp data
    return: pseudo_header: the pseudo TCP header
    '''
    pseudo_header = b''
    pseudo_header += source_ip
    pseudo_header += dest_ip
    pseudo_header += b'\x00'  # Zero checksum
    pseudo_header += b'\x06'  # Protocol number for TCP
    pseudo_header += tcp_length.to_bytes(2, byteorder='big')
    return pseudo_header


def compute_checksum(data):
    '''
    This function computes the checksum of the tcp data by making a
    list of integersfrom the tcp data and summing them (split every 2 bytes).
    Then it carries around the sum and returns the one's complement of the sum.

    param: data: the psuedo header and tcp data with zeroed checksum
    return: checksum: the checksum of the tcp data
    '''
    # convert data to a list of integers splitting every 2 bytes
    data_ints = list(map(lambda x: int.from_bytes(x, byteorder='big'), [data[i:i+2] for i in range(0, len(data), 2)]))
    # compute the sum of the integers
    checksum = sum(data_ints)
    # compute and carry around
    checksum = (checksum & 0xffff) + (checksum >> 16)
    # return the one's complement of the checksum
    return ~checksum & 0xffff


def validate(file_nums):
    '''
    This function validates the checksums of the tcp data in provide files by
    reading the ip addresses and tcp data from the files, generating pseudo
    headers, zeroing out the original checksums, computing new checksums,
    and comparing the computed checksums to the original checksums.

    calls: generate_pseudo_header, compute_checksum as helper functions
    param: file_nums: a list of file numbers to validate
    return: None
    '''
    # use map to read ip addresses from files and split them
    ip_addresses = map(lambda x: open('files/tcp_addrs_'+str(x)+'.txt').read().strip().split(' '), file_nums)

    # use inverse zip to split ip addresses into source and destination
    source_ip, dest_ip = zip(*ip_addresses)

    # convert to byte strings
    source_ip = list(map(lambda x: bytes(map(int, x.split('.'))), source_ip))
    dest_ip = list(map(lambda x: bytes(map(int, x.split('.'))), dest_ip))

    # use map to read tcp data from files into lists
    tcp_data = list(map(lambda x: open('files/tcp_data_'+str(x)+'.dat', 'rb').read(), file_nums))
    tcp_len = list(map(len, tcp_data))

    # generate pseudo headers
    psuedo_headers = list(map(generate_pseudo_header, source_ip, dest_ip, tcp_len))

    # zero out the checksums in the tcp data and pad if necessary
    tcp_zero_checksums = list(map(lambda x: x[:16]+b'\x00\x00'+x[18:] if len(x) % 2 == 0 else x[:16]+b'\x00\x00'+x[18:]+b'\x00', tcp_data))

    # compute the checksums by calling compute_checksum on the pseudo headers and zeroed tcp data
    checksums = list(map(compute_checksum, [b"".join(x) for x in zip(psuedo_headers, tcp_zero_checksums)]))

    # read the original checksums
    original_checksums = list(map(lambda x: int.from_bytes(x[16:18], byteorder='big'), tcp_data))

    # compare checksums and print the results
    print(*['PASS' if x[0] == x[1] else 'FAIL' for x in zip(checksums, original_checksums)], sep='\n')


def main():
    # generate file numbers
    file_nums = np.arange(10)
    # run the validator
    validate(file_nums)


if __name__ == '__main__':
    main()
