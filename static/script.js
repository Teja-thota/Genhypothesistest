let timerElement = document.getElementById('timer');
let duration = parseInt(timerElement.dataset.duration); // seconds
let interval = setInterval(() => {
    if(duration <= 0){
        clearInterval(interval);
        document.getElementById('examForm').submit();
    }
    let mins = Math.floor(duration/60);
    let secs = duration % 60;
    timerElement.innerText = mins + ":" + (secs < 10 ? "0"+secs : secs);
    duration--;
},1000);

function markBox(id, status){
    let box = document.getElementById('qbox_'+id);
    box.classList.remove('visited','saved');
    if(status === 'visited') box.classList.add('visited');
    else if(status === 'saved') box.classList.add('saved');
}

function goToQuestion(id){
    let q = document.getElementById('q_'+id);
    q.scrollIntoView({behavior:'smooth', block:'center'});
    markBox(id,'visited');
}

function saveQuestion(id){
    markBox(id,'saved');
}

function nextQuestion(index){
    let questions = document.querySelectorAll('.question');
    if(index+1 < questions.length){
        let nextQ = questions[index+1];
        nextQ.scrollIntoView({behavior:'smooth', block:'center'});
        let nextId = nextQ.id.split('_')[1];
        markBox(nextId,'visited');
    }
}

