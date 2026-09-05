import React from 'react';

function Comment({ html }: { html: string }) {
  return (
    <div>
      {/* ruleid: xss-dangerously-set */}
      <div className="body" dangerouslySetInnerHTML={{__html: html}} />
    </div>
  );
}

function Safe({ text }: { text: string }) {
  // ok: xss-dangerously-set
  return <p>{text}</p>;
}
