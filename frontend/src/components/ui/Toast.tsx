import { motion, AnimatePresence } from "framer-motion";

export interface ToastMessage {
  id: string;
  type: "success" | "error" | "info";
  message: string;
}

interface ToastProps {
  items: ToastMessage[];
  onDismiss: (id: string) => void;
}

const toastVariants = {
  hidden: { opacity: 0, y: 10, scale: 0.98 },
  show: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.2 } },
  exit: { opacity: 0, y: 10, transition: { duration: 0.2 } },
};

export function Toast({ items, onDismiss }: ToastProps) {
  return (
    <div className="fixed right-6 top-24 z-50 space-y-3">
      <AnimatePresence>
        {items.map((toast) => (
          <motion.div
            key={toast.id}
            variants={toastVariants}
            initial="hidden"
            animate="show"
            exit="exit"
            className={`rounded-xl border border-white/10 px-4 py-3 text-sm shadow-lg backdrop-blur-xl ${
              toast.type === "success"
                ? "bg-emerald-500/20 text-emerald-200"
                : toast.type === "error"
                ? "bg-red-500/20 text-red-200"
                : "bg-cyan-500/20 text-cyan-100"
            }`}
            onClick={() => onDismiss(toast.id)}
          >
            {toast.message}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
