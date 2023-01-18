# frozen_string_literal: true

class ThreadPool
  class << self
    attr_accessor :threads

    def stop_threads
      threads.each(&:kill)
      threads.clear
    rescue => e
      $stderr.puts e
    end

    def register_thread(thread)
      threads.push(thread)
    end
  end

  self.threads = Concurrent::Array.new

  def initialize(threads = 10)
    @threads = threads
    @pool = Concurrent::FixedThreadPool.new(@threads)
  end

  def post(&block)
    @pool.post do
      begin
        self.class.register_thread(Thread.current)

        block.call
      rescue => e
        $stderr.puts e
      end
    end
  end

  def finish
    @pool.shutdown
    @pool.wait_for_termination
  rescue Interrupt
    self.class.stop_threads
    nil
  end
end

def with_pool(threads = 10)
  pool = ThreadPool.new(threads)

  yield pool

  pool.finish
end
