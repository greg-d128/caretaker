ARG PYTHON_BASE_IMAGE=python:3.13-slim
FROM ${PYTHON_BASE_IMAGE}

# This image contains only the repository-owned, stdlib application laboratory.
# It is not a Caretaker runtime image and receives no application credentials,
# evidence store, source checkout, or network access at execution time.
RUN groupadd --gid 10001 caretaker \
    && useradd --uid 10001 --gid 10001 \
       --home-dir /nonexistent --no-create-home \
       --shell /usr/sbin/nologin caretaker \
    && mkdir -p /opt/caretaker/work \
    && chown root:root /opt/caretaker /opt/caretaker/work \
    && chmod 0555 /opt/caretaker /opt/caretaker/work

COPY application_laboratory.py /opt/caretaker/application_laboratory.py
RUN chown root:root /opt/caretaker/application_laboratory.py \
    && chmod 0444 /opt/caretaker/application_laboratory.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

USER 10001:10001
WORKDIR /opt/caretaker/work
ENTRYPOINT ["python", "/opt/caretaker/application_laboratory.py"]
