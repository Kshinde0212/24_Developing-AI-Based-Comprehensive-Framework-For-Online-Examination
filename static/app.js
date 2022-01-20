var nos;
var curr = 0;
var data = {};
const NOT_MARKED=0;
const MARKED=1;
const BOOKMARKED=2;
const MARKED_BOOKMARKED=3;
const SUBMITTED = 4;
const SUBMITTED_BOOKMARKED = 5;

function mySnackBar() {
    var x = document.getElementById("snackbar");
    x.className = "show";
    setTimeout(function(){ x.className = x.className.replace("show", ""); }, 10000);
  }


window.onfocus = function(event) {
    mySnackBar();
    $.ajax({
                  data : {'testid': tid},
                  type: "POST",
                  url: "/window_event"   
                });
};

var stream = document.getElementById("stream");
var capture = document.getElementById("capture");
var cameraStream = null;

function startStreaming() {
  
    var mediaSupport = 'mediaDevices' in navigator;
    navigator.getUserMedia = navigator.getUserMedia ||
    navigator.webkitGetUserMedia ||
    navigator.mozGetUserMedia;

    if( mediaSupport && null == cameraStream ) {
      navigator.mediaDevices.getUserMedia( { video: true, audio: true } )
      .then( function( mediaStream ) {
        cameraStream = mediaStream;
        stream.srcObject = mediaStream;
        stream.play();
        audioContext = new AudioContext();
        analyser = audioContext.createAnalyser();
        microphone = audioContext.createMediaStreamSource(mediaStream);
        javascriptNode = audioContext.createScriptProcessor(2048, 1, 1);
  
        analyser.smoothingTimeConstant = 0.8;
        analyser.fftSize = 1024;
  
        microphone.connect(analyser);
        analyser.connect(javascriptNode);
        javascriptNode.connect(audioContext.destination);
  
        javascriptNode.onaudioprocess = function() {
            array = new Uint8Array(analyser.frequencyBinCount);
            analyser.getByteFrequencyData(array);
            values = 0;
    
            length = array.length;
            for (var i = 0; i < length; i++) {
              values += (array[i]);
            }
        }
      })
      .catch( function( err ) {
        console.log("Unable to access camera: " + err);
      });
    }
    else {
      alert('Your browser does not support media devices.');
      return;
    }
  }
  
  function stopStreaming() {
  
    if( null != cameraStream ) {
      var track = cameraStream.getTracks()[ 0 ];
      track.stop();
      stream.load();
      cameraStream = null;
    }
  }
  
  function captureSnapshot() {
  
    if( null != cameraStream ) {
      var ctx = capture.getContext( '2d' );
      var img = new Image();
      ctx.drawImage( stream, 0, 0, capture.width, capture.height );
      img.src = capture.toDataURL( "image/png" );
      img.width = 340;
      var d1 = capture.toDataURL("image/png");
      var res = d1.replace("data:image/png;base64,", "");

        var average = values / length;

        console.log(average)
        console.log(Math.round(average - 40));

        if(average)
        {
            $.post("/video_feed",{
                /* data : {'imgData':res,'voice_db':average,'testid': tid}}, */
                data : {'imgData':res,'voice_db':average}},
                function(data){
                console.log(data);
                });
        }

      } 
      setTimeout(captureSnapshot, 5000);
    }

$(document).ready( function() {
    var url = window.location.href;
    var list = url.split('/');
    if (url.includes('/give-test/')) {
        $.ajax({
            type:"POST",
            url:"/randomize",
            dataType:"json",
            data : {id: list[list.length-1]},
            success: function(temp) {
                nos = temp;
                display_ques(1);
                make_array();
            }
        });
    }
    var time = parseInt($('#time').text()), display = $('#time');
    startTimer(time, display);
    sendTime();
    flag_time = true;
})

var unmark_all = function() {
    $('#options td').each(function(i) 
    {
        $(this).css("background-color",'rgba(0, 0, 0, 0)');
    });
}

var display_ques = function(move) {
    unmark_all();
    $.ajax({
        type: "POST",
        dataType: 'json',
        data : {flag: 'get', no: nos[curr]},
        success: function(temp) {
            $('#que').text(temp['q']);
            $('#a').text('𝐀.  '+temp['a']);
            $('#b').text('𝐁.  '+temp['b']);
            $('#c').text('𝐂.  '+temp['c']);
            $('#d').text('𝐃.  '+temp['d']);
            $('#queid').text('Question No. '+ (move));
            $('#mark').text('Marks: '+temp['marks']);
            if(data[curr+1].marked != null)
               $('#' + data[curr+1].marked).css("background-color",'rgba(0, 255, 0, 0.6)');
        },
        error: function(error){
            console.log("Here is the error res: " + JSON.stringify(error));
        }
    });
}
var flag_time = true;
function startTimer(duration, display) {
    var timer = duration,hours, minutes, seconds;
    
    var interval = setInterval(function () {
        console.log(timer);
        hours = parseInt(timer / 3600 ,10);
        minutes = parseInt((timer%3600) / 60, 10);
        seconds = parseInt(timer % 60, 10);
        hours = hours < 10 ? "0" + hours : hours;
        minutes = minutes < 10 ? "0" + minutes : minutes;
        seconds = seconds < 10 ? "0" + seconds : seconds;

        display.text(hours + ":" + minutes + ":" + seconds);

        if (--timer < 0) {
            finish_test();
            clearInterval(interval);
            flag_time = false;
        }
    }, 1000);
}

function finish_test() {
    $('#msg').addClass('alert-info');
    $('#msg').append("Test submitted successfully");
    $.ajax({
        type: "POST",
        dataType: "json",
        data: {flag: 'completed'},
        success: function(data) {
            window.location.replace('/student_dashboard');
        }
    });
    
}
function sendTime() {
    var intervalTime = setInterval(function() {
        if(flag_time == false){
            clearInterval(intervalTime);
        }
        var time = $('#time').text();
        var [hh,mm,ss] = time.split(':');
        hh = parseInt(hh);
        mm = parseInt(mm);
        ss = parseInt(ss);
        var seconds = hh*3600 + mm*60 + ss;
        $.ajax({
            type: 'POST',
            dataType: "json",
            data: {flag:'time', time: seconds},
        });
        if(flag_time == false){
            clearInterval(intervalTime);
        }
    }, 5000);
}
$(document).on('click', '#next', function(e){
    e.preventDefault();
    curr += 1;
    display_ques(curr+1);
    
});

$(document).on('click', '#prev', function(e){
    e.preventDefault();
    curr -= 1;
    display_ques(curr+1);
    
});

$('#submit').on('click', function(e){
    e.preventDefault();
    var marked;
    if(flag_time == false){
        window.location.replace('/student_dashboard');
        return;
    }
    $('#options td').each(function(i) 
    {
        if($(this).css("background-color") != 'rgba(0, 0, 0, 0)'){
            marked =  $(this).attr('id');
            data[curr+1].marked= marked;
            data[curr+1].status = SUBMITTED;
        }
    });
    $.ajax({
        type: "POST",
        dataType: 'json',
        data : {flag: 'mark', qid: nos[curr], ans: marked},
        success: function(data) {
            console.log('Answer posted')
        },
        error: function(error){
            console.log("Here is the error res: " + JSON.stringify(error));
        }
    });
    $('#next').trigger('click');
});

 function onn() {
    $('.question').remove();
    document.getElementById("overlay").style.display = "block";
    $('#question-list').append('<div id="close">X</div>');
    $('#close').on('click', function(e){
        off();
    });
} 

function off() {
    document.getElementById("overlay").style.display = "none";
    $('#close').remove();
} 

$('#questions').on('click', function(e){
    onn();
    for(var i=1;i<=nos.length;i++) {
        var color = '';
        var status = data[i].status;
        if(status == NOT_MARKED)
            color = '#1976D2';
        else if(status == SUBMITTED)
            color = '#42ed62';
        else if(status == BOOKMARKED || status == SUBMITTED_BOOKMARKED)
            color = '#e6ed7b';
        else{
            color = '#f44336';
        }
        j = i<10 ? "0" + i: i
        $('#question-list').append('<div class="question" style="background-color:' + color + '; color:white;">' + j + '</div>');
    }
    $('.question').click(function() {
        var id = parseInt($(this).text());
        curr = id-1;
        display_ques(curr+1);
        off();
    });

});


$('#bookmark').on('click', function(e){
    var status = data[curr+1].status;
    if( status == MARKED)
        data[curr+1].status = MARKED_BOOKMARKED;
    else if(status == SUBMITTED)
        data[curr+1].status = SUBMITTED_BOOKMARKED;
    else
        data[curr+1].status = BOOKMARKED;
});



$('#options').on('click', 'td', function(){
    if ($(this).css("background-color") != 'rgba(0, 255, 0, 0.6)') {
        var clicked = $(this).attr('id');
        var que = $('#queid').attr('id');
        unmark_all();
        $(this).css("background-color",'rgba(0, 255, 0, 0.6)');
        data[curr+1].status = MARKED;
        data[curr+1].marked = $(this).attr('id');
    }
    else {
        $(this).css("background-color",'rgba(0, 0, 0, 0)');
        data[curr+1].status = NOT_MARKED;
        data[curr+1].marked = null;
    }
});

var submit_overlay_display = true;
$('#finish').on("click", function(e) {
    $('#submit-overlay').empty();
    var count = marked();
    var remaining = nos.length - count;
    if(submit_overlay_display) {
        document.getElementById("submit-overlay").style.display = "block";
        $('#submit-overlay').append('<div style="background-color:white; display: inline-block;/*! margin: auto; *//*! margin: 0 auto; */position: absolute;left: 40%;top: 33%;padding: 10PX; width:30%;" align="center"><table class="table"> <tr><td>Total Questions</td><td>Attempted</td><td>Remaining</td></tr><tr><td>'+ nos.length +'</td><td>'+ count +'</td><td>'+ remaining +'</td></tr></table> <a class="btn btn-primary" onclick="finish_test();">Submit Test</a></div>');
        submit_overlay_display=false;
    } else {
        document.getElementById("submit-overlay").style.display = "none";
        submit_overlay_display = true;
    }
});

var marked = function() {
    var count = 0;
    for(var i=1;i<=nos.length;i++){
        if(data[i].status == SUBMITTED || data[i].status == SUBMITTED_BOOKMARKED){
            count++;
        } 
    }
    return count;
}

var make_array = function() {
    for(var i=0; i<nos.length; i++){
        data[i+1] = {marked : null, status: NOT_MARKED}; 
    }
    var txt = document.createElement('textarea');
    txt.innerHTML = answers;
    answers = txt.value;
    answers = JSON.parse(answers);
    for(var key in answers) {
        data[parseInt(key)+1].marked = answers[key]
        data[parseInt(key)+1].status = SUBMITTED;
    }
}


window.addEventListener('blur', function() { 
    window.location.replace('/student_dashboard');
 }); 
