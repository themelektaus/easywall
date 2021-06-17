var countdown = document.getElementById("countdown");

if (countdown != null) {
  var accepttime = document.getElementById("accepttime");
  if (accepttime != null) {
    accepttime = accepttime.getAttribute("data");
  }

  var target = new Date();
  target.setSeconds(target.getSeconds() + accepttime);
  target = target.getTime();

  var seconds, now, distance;

  setInterval(function () {
    now = new Date().getTime();
    distance = target - now;
    seconds = Math.floor((distance % (1000 * accepttime)) / 1000);
    countdown.innerHTML = seconds;
  }, 1000);

  setInterval(function () {
    var form = document.createElement("form");
    form.method = "post";
    form.action = "/apply-save";
    var input = document.createElement("input");
    input.type = "text";
    input.name = "step_timeout";
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
  }, accepttime * 1000);
}

$(document).ready(() => {
  setTimeout(() => $(".jumbotron .container").addClass("visible"), 50);
  setTimeout(() => $("body > .container").addClass("visible"), 100);
  $('.dashboard-item').each(function(i) {
    setTimeout(() => $(this).addClass("visible"), 300 + i * 70);
  });
  
  $('#flashesModal').modal('show');
  
  function autoSizeFieldUpdate(text) {
    if (!text.trim()) {
        const placeholder = $(this).attr('placeholder');
        if (placeholder) {
          text = placeholder.trim();
        }
    }
    const $span = $(this).parent().find('span');
    $span.text(text);
    $(this).css("width", $span.width() + 10);
  }
  $('.auto-size-field > input').keypress(function (e) {
      if (e.which && e.charCode) {
        const c = String.fromCharCode(e.keyCode | e.charCode);
        autoSizeFieldUpdate.call($(this), $(this).val() + c);
      }
  });
  $('.auto-size-field > input').keyup(function (e) { 
    if (e.keyCode === 8 || e.keyCode === 46) {
      autoSizeFieldUpdate.call($(this), $(this).val());
    }
  });
  $('.auto-size-field > input').each(function () {
    autoSizeFieldUpdate.call($(this), $(this).val())
  });
  
});