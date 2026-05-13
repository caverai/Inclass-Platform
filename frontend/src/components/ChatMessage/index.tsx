import React from 'react';
import { BookOpenCheck, Sparkles, UserRound } from 'lucide-react';
import type { StudentChatMessage } from '../../api/studentApi';

interface ChatMessageProps {
  message: StudentChatMessage;
}

export const ChatMessage: React.FC<ChatMessageProps> = ({ message }) => {
  const isStudent = message.sender === 'student';

  return (
    <div className={`flex w-full ${isStudent ? 'justify-end' : 'justify-start'}`}>
      <div className={`flex max-w-[88%] gap-3 sm:max-w-[74%] ${isStudent ? 'flex-row-reverse' : 'flex-row'}`}>
        <div
          className={`mt-1 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full ${
            isStudent ? 'bg-indigo-600 text-white' : 'bg-emerald-100 text-emerald-700'
          }`}
        >
          {isStudent ? <UserRound className="h-4 w-4" /> : <BookOpenCheck className="h-4 w-4" />}
        </div>

        <div className="min-w-0">
          <div
            className={`whitespace-pre-line rounded-lg px-4 py-3 text-sm leading-6 shadow-sm ${
              isStudent
                ? 'bg-indigo-600 text-white'
                : message.isCelebration
                  ? 'border border-emerald-200 bg-emerald-50 text-emerald-950'
                  : 'border border-gray-200 bg-white text-gray-800'
            }`}
          >
            {message.content}
          </div>

          {message.miniLesson && (
            <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950 shadow-sm">
              <div className="mb-1 flex items-center gap-2 font-semibold">
                <Sparkles className="h-4 w-4 text-amber-600" />
                Mini Lesson
              </div>
              <p className="leading-6">{message.miniLesson}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
