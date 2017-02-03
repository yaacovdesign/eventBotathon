/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

const {Wit, log} = require('node-wit');

var app = express();
app.set('port', process.env.PORT || 3978);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}


// Server LoL 
const SERVER_LOL = (process.env.SERVER_LOL) ?
    (process.env.SERVER_LOL) :
    config.get('serverLOL');

const API_KEY = (process.env.API_KEY) ?
    (process.env.API_KEY) :
    config.get('api_key');
// End Server LoL

// Actions on LOL API
const SUMMONER_BY_NAME = '/summoner/by-name/';


// End Actions on LoL API

// Status User
let user = {
  name: '',
  summonerName: '',
  email: ''
}

// End Status Usuer

// Webhook
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});

app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    res.sendStatus(200);
  }
});
// End Webhook

// Authorization Account Linking
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});


function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  sendTextMessage(senderID, "Authentication successful");
}
// Authorization Account Linking


/*
 * Message Event
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

      switch(quickReplyPayload) {
        case "CREATE_USER":
           createUser(senderID);
        break;

        case "NAME_FAIL":
          user.name = '';
          inputNameAgain(senderID, "Vamos tentar novamente, digite o seu nome. Plz!");
        break;

        case "NAME_OK":
          sendSuccesImageMessage(senderID);
          sendQuickReplyRepeat(senderID, "Isso aí!!! Agora vamos para diversão.")
        break;

        case "CREATE_TEAM":
          sendTextMessage(senderID, "Voce escolheu, " + quickReplyPayload);
        break;

        case "CREATE_TOURNAMENT":
          sendTextMessage(senderID, "Voce escolheu, " + quickReplyPayload);
        break;

        case "JOIN_TEAM":
          sendTextMessage(senderID, "Voce escolheu, " + quickReplyPayload);
        break;

        case "JOIN_TEAM":
          sendTextMessage(senderID, "Voce escolheu, " + quickReplyPayload);
        break;

        default:
          sendTextMessage(senderID, "Quick reply tapped");
        break;
      }

    return;
  }

  if (user.name == '' ) {
    getName(senderID, messageText);
  } else if (messageText) {

    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;        

      case 'read receipt':
        sendReadReceipt(senderID);
        break;        

      case 'typing on':
        sendTypingOn(senderID);
        break;        

      case 'typing off':
        sendTypingOff(senderID);
        break;        

      case 'account linking':
        sendAccountLinking(senderID);
        break;

      default:

        sendTextMessage(senderID, messageText);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}


/*
 * Delivery Confirmation Event
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }
  console.log("sender ID: %s ",senderID);
  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

    if(payload == "START") {
      sendQuickReplyInitial(senderID, "Seja bem vindo! Selecione umas das opções para iniciarmos nossa jornada!");
    } else {
      sendTextMessage(senderID, payload);
    }
}

/*
* Info from LoL Server
*/
function getFirstName (id) {
    var options = { 
        method: 'GET',
        url: 'https://graph.facebook.com/v2.6/'+id,
        qs: { 
            fields: 'first_name',
            access_token: PAGE_ACCESS_TOKEN
        }
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(error);
        console.log(body);

        var data = JSON.parse(body);

        user.name = data.first_name;

        var initialMessage = 'Hi '+user.name+', seja bem vindo. Vamos começar pelo seu summoner name, digite-o por favor.';
        sendSummonerTextMessage(id, initialMessage);
    });
}

function getName (id, textInputed) {
    var messageData = {
    recipient: {
      id: id
    },
    message: {
      text: textInputed+", certo?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"sim",
          "payload":"NAME_OK"
        },
        {
          "content_type":"text",
          "title":"não",
          "payload":"NAME_FAIL"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function checkNameTextMessage (id, textInputed) {
    var messageData = {
    recipient: {
      id: id
    },
    message: {
      text: textInputed+", certo?",
      quick_replies: [
         {
          "content_type":"text",
          "title":"Criar usuário",
          "payload":"CREATE_USER"
        },
        {
          "content_type":"text",
          "title":"Criar time",
          "payload":"CREATE_TEAM"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function sendSuccesImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/sucesso.jpg"
        }
      }
    }
  };

  callSendAPI(messageData);
}

function getSummonerName (id, textInputed) {
  // clean string of username
  user.summonerName = textInputed.replace(/\s/g, '');
  var url = SERVER_LOL.concat(SUMMONER_BY_NAME, user.summonerName);
  var options = {
    method: 'GET',
    url: url,
    qs: {
      api_key: API_KEY
    }
  };

  request(options, function(error, response, body) {
     if (error) throw new Error(error);
     console.log(body);

     console.log(user.summonerName);
     
     var data = JSON.parse(body);
     console.log(data[user.summonerName].name);

    if(data[user.summonerName] != undefined) {
      user.summonerName = data[user.summonerName].name;
      sendQuickReplySuccessSummoner(id, "Verificamos com sucesso seu usuário");
    } else {
      user.summonerName = '';
      sendTextMessage(id, "Não conseguimos encontrar seu usuário, por favor digite novamente.");
    }
  });
}

/*
* End Info from LoL Server
*/


/*
* Tournament service
*/
function createUser(senderID) {
  sendTextMessage(senderID, "Vamos lá! Qual o seu  nome?");
}

function createTeam(senderID) {
  
}

function createTournament(senderID) {
  
}

function joinTeam(senderID) {
  
}

function joinTournament(senderID) {
  
}

/*
* End Tournament service
*/

/*
 * Message Read Event
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 */
// function sendVideoMessage(recipientId) {
//   var messageData = {
//     recipient: {
//       id: recipientId
//     },
//     message: {
//       attachment: {
//         type: "video",
//         payload: {
//           url: SERVER_URL + "/assets/allofus480.mov"
//         }
//       }
//     }
//   };

//   callSendAPI(messageData);
// }

/*
 * Send a file using the Send API.
 */
// function sendFileMessage(recipientId) {
//   var messageData = {
//     recipient: {
//       id: recipientId
//     },
//     message: {
//       attachment: {
//         type: "file",
//         payload: {
//           url: SERVER_URL + "/assets/test.txt"
//         }
//       }
//     }
//   };

//   callSendAPI(messageData);
// }

/*
 * Send a text message using the Send API.
 *
 */
function sendSummonerTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText
    }
  };

  callSendAPI(messageData);
}

function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",               
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",               
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function sendQuickReplyInitial(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      quick_replies: [
         {
          "content_type":"text",
          "title":"Criar usuário",
          "payload":"CREATE_USER"
        },
        {
          "content_type":"text",
          "title":"Criar time",
          "payload":"CREATE_TEAM"
        },
        {
          "content_type":"text",
          "title":"Criar campeonato",
          "payload":"CREATE_TOURNAMENT"
        },
        {
          "content_type":"text",
          "title":"Entrar time",
          "payload":"JOIN_TEAM"
        },
        {
          "content_type":"text",
          "title":"Entrar campeonato",
          "payload":"JOIN_TOURNAMENT"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function sendQuickReplyRepeat(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      quick_replies: [
        {
          "content_type":"text",
          "title":"Criar time",
          "payload":"CREATE_TEAM"
        },
        {
          "content_type":"text",
          "title":"Criar campeonato",
          "payload":"CREATE_TOURNAMENT"
        },
        {
          "content_type":"text",
          "title":"Entrar time",
          "payload":"JOIN_TEAM"
        },
        {
          "content_type":"text",
          "title":"Entrar campeonato",
          "payload":"JOIN_TOURNAMENT"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}


function menuPersistent(recipientId) {
    // var messageData =
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

function setup () {
  // Setting up Start Button
request({
  uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
  qs: { access_token: PAGE_ACCESS_TOKEN },
  method: 'POST',
  json: {
    "setting_type":"call_to_actions",
    "thread_state":"new_thread",
    "call_to_actions":[
      {
        "payload":"START"
      }
    ]
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      console.log('setting up start Button.');
    }
    else {
      console.log(error);
    }
  }
});
// End Setting up Start Button

// Setting up Start Button
request({
  uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
  qs: { access_token: PAGE_ACCESS_TOKEN },
  method: 'POST',
  json:{
    "setting_type":"greeting",
    "greeting":{
      "text":"Olá {{user_first_name}}, seja bem vindo ao Torneio Maker Bot."
    }
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      console.log('setting up welcome text');
    } else {
      console.log(error);
    }
  }
});
// End Setting up Start Button

// Menu persistent
request({
  uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
  qs: { access_token: PAGE_ACCESS_TOKEN },
  method: 'POST',
  json:{
  "setting_type" : "call_to_actions",
  "thread_state" : "existing_thread",
  "call_to_actions":[
    {
      "type":"postback",
      "title":"Ajuda",
      "payload":"MENU_HELP"
    },
    {
      "type":"postback",
      "title":"Encontrar Torneio",
      "payload":"FIND_TOURNMENT"
    },
    {
      "type":"postback",
      "title":"Encontrar Time",
      "payload":"FIND_TEAM"
    },
    {
      "type":"postback",
      "title":"informações",
      "url":"https://www.facebook.com/Torneio-maker-bot-101132157069633/",
      "webview_height_ratio": "full",
      "messenger_extensions": true
    }
  ]
}, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      console.log('setting up menu persistent');
    } else {
      console.log(error);
    }
  }
});

setup();

// End Menu Persistent
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});



module.exports = app;

