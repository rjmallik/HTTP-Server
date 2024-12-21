#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <stdbool.h>
#include "asgn2_helper_funcs.h"
#include "debug.h"
#include "protocol.h"

#define DATA_BUFFER_SIZE 4096

typedef struct HttpRequest {
    char *method_type;
    char *file_path;
    char *http_version;
    char *body_data;
    int client_fd;
    ssize_t content_size;
    ssize_t bytes_pending;
} HttpRequest;

void release_request(HttpRequest *req) {
    if (req) {
        if (req->client_fd >= 0) {
            close(req->client_fd);
            req->client_fd = -1;
        }
    }
}

int handle_get(HttpRequest *req) {
    struct stat file_info;
    if (!req || !req->file_path) {
        return EXIT_FAILURE;
    }
    if (stat(req->file_path, &file_info) == -1) {
        switch (errno) {
        case ENOENT:
            dprintf(req->client_fd,
                "HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\n\r\nNot Found\n", 10);
            break;
        case EACCES:
            dprintf(req->client_fd,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\nForbidden\n", 10);
            break;
        default:
            dprintf(req->client_fd,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: %d\r\n\r\nInternal Server "
                "Error\n",
                22);
        }
        return EXIT_FAILURE;
    }
    if (S_ISDIR(file_info.st_mode)) {
        dprintf(
            req->client_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\nForbidden\n", 10);
        return EXIT_FAILURE;
    }
    int file_desc = open(req->file_path, O_RDONLY);
    if (file_desc == -1) {
        dprintf(req->client_fd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: %d\r\n\r\nInternal Server "
            "Error\n",
            22);
        return EXIT_FAILURE;
    }
    if (dprintf(req->client_fd, "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", file_info.st_size)
        < 0) {
        close(file_desc);
        return EXIT_FAILURE;
    }
    char data_buffer[DATA_BUFFER_SIZE];
    ssize_t remaining_size = file_info.st_size;

    while (remaining_size > 0) {
        size_t read_size = (remaining_size > DATA_BUFFER_SIZE) ? DATA_BUFFER_SIZE : remaining_size;
        ssize_t bytes_read = read(file_desc, data_buffer, read_size);

        if (bytes_read <= 0) {
            close(file_desc);
            return EXIT_FAILURE;
        }

        ssize_t bytes_written = write(req->client_fd, data_buffer, bytes_read);
        if (bytes_written != bytes_read) {
            close(file_desc);
            return EXIT_FAILURE;
        }

        remaining_size -= bytes_read;
    }
    close(file_desc);
    return EXIT_SUCCESS;
}

int handle_put(HttpRequest *req) {
    if (req->content_size == -1) {
        dprintf(req->client_fd,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\nBad Request\n", 12);
        return EXIT_FAILURE;
    }
    struct stat path_stats;
    if (stat(req->file_path, &path_stats) == 0 && S_ISDIR(path_stats.st_mode)) {
        dprintf(
            req->client_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\nForbidden\n", 10);
        return EXIT_FAILURE;
    }
    int response_code = 0;
    int file_desc;
    if ((file_desc = open(req->file_path, O_WRONLY | O_DIRECTORY, 0666)) != -1) {
        dprintf(
            req->client_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\nForbidden\n", 10);
        return EXIT_FAILURE;
    }
    if ((file_desc = open(req->file_path, O_WRONLY | O_CREAT | O_EXCL, 0666)) == -1) {
        if (errno == EEXIST) {
            response_code = 200;
        } else if (errno == EACCES) {
            dprintf(req->client_fd,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\nForbidden\n", 10);
            return EXIT_FAILURE;
        } else {
            dprintf(req->client_fd,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: %d\r\n\r\nInternal Server "
                "Error\n",
                22);
            return EXIT_FAILURE;
        }
    } else if (file_desc != -1) {
        response_code = 201;
    }

    if (response_code == 200) {
        if ((file_desc = open(req->file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666)) == -1) {
            if (errno == EACCES) {
                dprintf(req->client_fd,
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\nForbidden\n", 10);
                return EXIT_FAILURE;
            } else {
                dprintf(req->client_fd,
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: %d\r\n\r\nInternal "
                    "Server Error\n",
                    22);
                return EXIT_FAILURE;
            }
        }
    }
    int written_bytes = write_n_bytes(file_desc, req->body_data, req->bytes_pending);
    if (written_bytes == -1) {
        dprintf(req->client_fd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: %d\r\n\r\nInternal Server "
            "Error\n",
            22);
        return EXIT_FAILURE;
    }
    int total_bytes = req->content_size - req->bytes_pending;
    written_bytes = pass_n_bytes(req->client_fd, file_desc, total_bytes);
    if (written_bytes == -1) {
        dprintf(req->client_fd,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: %d\r\n\r\nInternal Server "
            "Error\n",
            22);
        return EXIT_FAILURE;
    }
    if (response_code == 201) {
        dprintf(req->client_fd, "HTTP/1.1 201 Created\r\nContent-Length: %d\r\n\r\nCreated\n", 8);
    } else {
        dprintf(req->client_fd, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\nOK\n", 3);
    }
    close(file_desc);
    return EXIT_SUCCESS;
}

int manage_request(HttpRequest *req);
int parse_client_request(HttpRequest *req, char *buffer, ssize_t buffer_length);

int manage_request(HttpRequest *req) {
    if (!req || !req->http_version || !req->method_type) {
        return EXIT_FAILURE;
    }
    if (strncmp(req->http_version, "HTTP/1.1", 8) != 0) {
        dprintf(req->client_fd,
            "HTTP/1.1 505 Version Not Supported\r\nContent-Length: %d\r\n\r\nVersion Not "
            "Supported\n",
            22);
        return EXIT_FAILURE;
    } else if (strncmp(req->method_type, "GET", 3) == 0) {
        return handle_get(req);
    } else if (strncmp(req->method_type, "PUT", 3) == 0) {
        return handle_put(req);
    } else {
        dprintf(req->client_fd,
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: %d\r\n\r\nNot Implemented\n", 16);
        return EXIT_FAILURE;
    }
}

int parse_client_request(HttpRequest *req, char *buffer, ssize_t buffer_length) {
    if (!req || !buffer || buffer_length <= 0) {
        return EXIT_FAILURE;
    }
    int offset = 0;
    regex_t pattern;
    regmatch_t matches[4];
    if (regcomp(&pattern, REQUEST_LINE_REGEX, REG_EXTENDED) != 0) {
        fprintf(stderr, "Request Line REGEX Failure\n");
        return EXIT_FAILURE;
    }
    if (regexec(&pattern, buffer, 4, matches, 0) == 0) {
        if (matches[3].rm_eo >= buffer_length) {
            regfree(&pattern);
            return EXIT_FAILURE;
        }

        req->method_type = buffer + matches[1].rm_so;
        req->file_path = buffer + matches[2].rm_so;
        req->http_version = buffer + matches[3].rm_so;

        buffer[matches[1].rm_eo] = '\0';
        buffer[matches[2].rm_eo] = '\0';
        buffer[matches[3].rm_eo] = '\0';

        buffer += matches[3].rm_eo + 2;
        offset = matches[3].rm_eo + 2;
    } else {
        dprintf(req->client_fd,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\nBad Request\n", 12);
        regfree(&pattern);
        return EXIT_FAILURE;
    }
    regfree(&pattern);

    if (strncmp(req->method_type, "GET", 3) == 0) {
        req->content_size = -1;
        req->bytes_pending = 0;
    } else {
        req->content_size = -1;
    }

    if (regcomp(&pattern, HEADER_FIELD_REGEX, REG_EXTENDED) != 0) {
        fprintf(stderr, "Header Field REGEX Failure\n");
        return EXIT_FAILURE;
    }
    while (offset < buffer_length && regexec(&pattern, buffer, 3, matches, 0) == 0) {

        if (matches[2].rm_eo >= (buffer_length - offset)) {
            regfree(&pattern);
            return EXIT_FAILURE;
        }

        buffer[matches[1].rm_eo] = '\0';
        buffer[matches[2].rm_eo] = '\0';

        if (strncmp(buffer, "Content-Length", 14) == 0) {
            char *endptr;
            errno = 0;
            long val = strtol(buffer + matches[2].rm_so, &endptr, 10);
            if (errno == EINVAL || *endptr != '\0' || val < 0) {
                dprintf(req->client_fd,
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\nBad Request\n", 12);
                regfree(&pattern);
                return EXIT_FAILURE;
            }
            req->content_size = val;
        }

        buffer += matches[2].rm_eo + 2;
        offset += matches[2].rm_eo + 2;
    }
    regfree(&pattern);
    if (offset + 2 <= buffer_length && buffer[0] == '\r' && buffer[1] == '\n') {
        req->body_data = buffer + 2;
        offset += 2;
        req->bytes_pending = buffer_length - offset;
        return EXIT_SUCCESS;
    }
    dprintf(
        req->client_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\nBad Request\n", 12);
    return EXIT_FAILURE;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        warnx("wrong arguments: %s port_num", argv[0]);
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *endptr = NULL;
    size_t port = (size_t) strtoull(argv[1], &endptr, 10);

    if (port < 1 || port > 65535 || *endptr != '\0') {
        fprintf(stderr, "Invalid Port\n");
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    Listener_Socket server_socket;
    if (listener_init(&server_socket, port) == -1) {
        fprintf(stderr, "Invalid Port\n");
        return EXIT_FAILURE;
    }

    while (1) {
        char buffer[DATA_BUFFER_SIZE + 1] = { '\0' };
        HttpRequest req = { 0 };
        req.client_fd = -1;
        req.content_size = -1;
        int client_fd = listener_accept(&server_socket);
        if (client_fd == -1) {
            fprintf(stderr, "Unable to Establish Connection\n");
            return EXIT_FAILURE;
        }
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        req.client_fd = client_fd;

        ssize_t received_bytes = 0;
        int retry_attempts = 0;
        while (retry_attempts < 3) {
            received_bytes = read_until(client_fd, buffer, DATA_BUFFER_SIZE, "\r\n\r\n");
            if (received_bytes > 0)
                break;
            if (received_bytes == -1 && errno != EINTR) {
                retry_attempts++;
            }
        }

        if (received_bytes <= 0) {
            dprintf(req.client_fd,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\nBad Request\n", 12);
            release_request(&req);
            continue;
        }
        buffer[received_bytes] = '\0';
        if (parse_client_request(&req, buffer, received_bytes) != EXIT_FAILURE) {
            manage_request(&req);
        }
        release_request(&req);
        memset(buffer, '\0', sizeof(buffer));
    }
    return EXIT_SUCCESS;
}
