const fs = require('fs');
const http = require('http');

const WebSocket = require('ws');
const uuid = require('uuid');
const SDPUtils = require('sdp');

const port = 8080;
 
// We use a HTTP server for serving static pages. In the real world you'll
// want to separate the signaling server and how you serve the HTML/JS, the
// latter typically through a CDN.
const server = http.Server({})
    .listen(port);
server.on('listening', () => {
    console.log('Server listening on http://localhost:' + port);
});
server.on('request', (request, response) => {
    fs.readFile('static/index.html', (err, data) => {
        if (err) {
            console.log('could not read client file', err);
            response.writeHead(404);
            response.end();
            return;
        }
        response.writeHead(200, {'Content-Type': 'text/html'});
        response.end(data);
    });
});

// A map of websocket connections.
const connections = new Map();
// WebSocket server, running alongside the http server.
const wss = new WebSocket.Server({server});

// Generate a (unique) client id.
// Exercise: extend this to generate a human-readable id.
function generateClientId() {
    // TODO: enforce uniqueness here instead of below.
    return uuid.v4();
}
 
wss.on('connection', (ws) => {
    // Assign an id to the client. The other alternative is to have the client
    // pick its id and tell us. But that needs handle duplicates. It is preferable
    // if you have ids from another source but requires some kind of authentication.
    const id = generateClientId();
    console.log(id, 'Received new connection');

    if (connections.has(id)) {
        console.log(id, 'Duplicate id detected, closing');
        ws.close();
        return;
    }
    // Store the connection in our map of connections.
    connections.set(id, ws);

    // Send a greeting to tell the client its id.
    ws.send(JSON.stringify({
        type: 'hello',
        id,
    }));

    // Send an ice server configuration to the client. For stun this is synchronous,
    // for TURN it might require getting credentials.
    ws.send(JSON.stringify({
        type: 'iceServers',
        iceServers: [{urls: 'stun:stun.l.google.com:19302'}],
    }));

    // Remove the connection. Note that this does not tell anyone you are currently in a call with
    // that this happened. This would require additional statekeeping that is not done here.
    ws.on('close', () => {
        console.log(id, 'Connection closed');
        connections.delete(id); 
    });

    ws.on('message', (message) => {
        console.log(id, 'received', message);
        let data;
        // TODO: your protocol should send some kind of error back to the caller instead of
        // returning silently below.
        try  {
            data = JSON.parse(message);
        } catch (err) {
            console.log(id, 'invalid json', err, message);
            return;
        }
        if (!data.id) {
            console.log(id, 'missing id', data);
            return;
        }

        if (data.type === 'offer') {
          try {
            const sections = SDPUtils.splitSections(data.sdp);
            sections.shift();
            for (let sdpMLineIndex = 0; sdpMLineIndex < sections.length; sdpMLineIndex++) {
              const kind = SDPUtils.getKind(sections[sdpMLineIndex]);
              if (!(['audio', 'video'].includes(kind))) {
                // SDP inspection to reject any non audio/video content. This means
                // the server will not let clients exchange datachannel SDP so
                // that a vulnerability like
                //   https://googleprojectzero.blogspot.com/2020/08/exploiting-android-messengers-part-3.html
                // is prevented. Note that native clients should also not include usrsctp
                // if they know that datachannels are not used.
                console.error(id, 'unknown media type detected', kind, sections[sdpMLineIndex]);
                // Drop the message, disconnect the offending client forcefully.
                ws.terminate();
                return;
              }
              // Remove any extmap lines. This prevents the RTP header extensions suspectible to
              //   https://googleprojectzero.blogspot.com/2020/08/exploiting-android-messengers-part-1.html
              // from being negotiated.
              // We still want the audio/video call to be negotiated so we remove the lines from the SDP.
              // This removes
              //   http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07
              //   http://www.webrtc.org/experiments/rtp-hdrext/video-timing
              // from both audio and video (just in case)
              const extensionsToFilter = [
                'http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07',
                'http://www.webrtc.org/experiments/rtp-hdrext/video-timing',
              ];
              const extensions = SDPUtils.matchPrefix(sections[sdpMLineIndex], 'a=extmap:');
              extensions.forEach(line => {
                const extension = SDPUtils.parseExtmap(line);
                if (extensionsToFilter.includes(extension.uri)) {
                  // Remove the line, in both possible variants since SDP allows both
                  // LF and CRLF as line separators.
                  data.sdp = data.sdp.replace(line + '\r\n', '');
                  data.sdp = data.sdp.replace(line + '\n', '');
                }
              });
            }
          } catch(e) {
            console.error(id, 'error while munging SDP', e.toString());
            // Drop the message, disconnect the offending client forcefully.
            ws.terminate();
            return;
          }
        }

        // The direct lookup of the other clients websocket is overly simplified.
        // In the real world you might be running in a cluster and would need to send
        // messages between different servers in the cluster to reach the other side.
        if (!connections.has(data.id)) {
            console.log(id, 'peer not found', data.id);
            // TODO: the protocol needs some error handling here. This can be as
            // simple as sending a 'bye' with an extra error element saying 'not-found'.
            return;
        }
        const peer = connections.get(data.id);

        // Stamp messages with our id. In the client-to-server direction, 'id' is the
        // client that the message is sent to. In the server-to-client direction, it is
        // the client that the message originates from.
        data.id = id;
        peer.send(JSON.stringify(data), (err) => {
            if (err) {
                console.log(id, 'failed to send to peer', err);
            }
        });
    });
});
